#!/usr/bin/env python3
"""
Medicover Appointment Monitor

Monitors availability of appointments with a specific specialist at a specific
Medicover clinic. Sends email notification when appointments become available.

Usage:
    # Check for appointments and send email if found:
    python monitor.py

    # Discover region / specialization / clinic / doctor IDs:
    python monitor.py --discover --region 204
    python monitor.py --discover --region 204 --specialization 27962
    python monitor.py --discover --region 204 --specialization 27962 --clinic 174

Environment variables (required for monitoring):
    MEDICOVER_USER        Medicover identyfikator (cyfry, nie email)
    MEDICOVER_PASS        Medicover password
    REGION_ID             Region ID (e.g. 204 = Warsaw)
    SPECIALIZATION_ID     Specialization ID (e.g. 27962 = Endocrinology)
    CLINIC_ID             Clinic ID (-1 = any)
    DOCTOR_ID             Doctor ID (-1 = any)
    DAYS_AHEAD            How many days ahead to search (default: 30)
    EMAIL_TO              Recipient email address
    SMTP_HOST             SMTP server (e.g. smtp.gmail.com)
    SMTP_PORT             SMTP port (default: 587)
    SMTP_USER             SMTP login
    SMTP_PASS             SMTP password / App Password
"""

import base64
import hashlib
import os
import random
import string
import sys
import json
import smtplib
import argparse
import logging
import time
import uuid
from datetime import date, datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from urllib.parse import parse_qs, urlparse, quote

import requests
import yaml
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Load .env file if present (local development convenience)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path, encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
    log.info("Załadowano zmienne środowiskowe z .env")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL  = "https://online24.medicover.pl"
LOGIN_URL = "https://login-online24.medicover.pl"
API_BASE  = "https://api-gateway-online24.medicover.pl"

SEARCH_ENDPOINT  = "/appointments/api/search-appointments/slots"
FILTERS_ENDPOINT = "/appointments/api/search-appointments/filters"
BOOK_ENDPOINT    = "/appointments/api/v2/search-appointments/book-appointment"

IMAP_HOST      = "imap.interia.pl"
IMAP_PORT      = 993
BOOKING_WAIT_S = int(os.environ.get("BOOKING_WAIT_SECONDS", "300"))  # override lokalnie
IMAP_POLL_S    = 5     # odpytuj IMAP co 5 sekund

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    ),
    "Accept-Language": "pl,en-US;q=0.7,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# Medicover session
# ---------------------------------------------------------------------------

class MedicoverSession:
    """Handles authentication and API calls against online24.medicover.pl."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    # ------------------------------------------------------------------
    # PKCE helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pkce_challenge(verifier: str) -> str:
        """Return base64url(SHA-256(verifier)) with no padding."""
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    # ------------------------------------------------------------------
    # Authentication  (OAuth2 Authorization Code + PKCE)
    # ------------------------------------------------------------------

    def log_in(self):
        """
        Authenticate against online24.medicover.pl using OAuth2 + PKCE.

        Flow (based on MediCzuwacz / atais/medibot reverse engineering):
          1. Generate PKCE code_verifier + code_challenge
          2. GET /connect/authorize  →  redirect to IS3 login page
          3. POST credentials (Input.Username / Input.Password + CSRF token)
          3.5 Skip MFA-gate if present
          4. Follow callback redirect to extract authorization code
          5. POST /connect/token → receive access_token
        """
        # --- PKCE + OAuth state ---
        code_verifier = "".join(uuid.uuid4().hex for _ in range(3))
        code_challenge = self._pkce_challenge(code_verifier)
        state = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
        device_id = str(uuid.uuid4())
        epoch_ms = int(time.time()) * 1000
        oidc_redirect = f"{BASE_URL}/signin-oidc"

        auth_params = (
            f"?client_id=web&redirect_uri={oidc_redirect}&response_type=code"
            f"&scope=openid+offline_access+profile&state={state}"
            f"&code_challenge={code_challenge}&code_challenge_method=S256"
            f"&response_mode=query&ui_locales=pl"
            f"&app_version=3.4.0-beta.1.0&previous_app_version=3.4.0-beta.1.0"
            f"&device_id={device_id}&device_name=Chrome&ts={epoch_ms}"
        )

        # Step 1 — initiate authorization (do NOT follow redirects manually)
        log.info("[Auth 1/5] GET %s/connect/authorize …", LOGIN_URL)
        resp = self.session.get(
            f"{LOGIN_URL}/connect/authorize{auth_params}",
            allow_redirects=False,
            timeout=30,
        )
        next_url = resp.headers.get("Location")
        log.info("[Auth 1/5] Redirect to: %s", next_url)

        # Step 2 — land on IS3 login page, extract CSRF token
        resp = self.session.get(next_url, allow_redirects=False, timeout=30)
        soup = BeautifulSoup(resp.content, "html.parser")
        csrf_input = soup.find("input", {"name": "__RequestVerificationToken"})
        if not csrf_input:
            raise AuthError(
                f"CSRF token not found on login page ({next_url}). "
                "Medicover mogło zmienić strukturę strony logowania."
            )
        csrf_token = csrf_input.get("value")
        log.info("[Auth 2/5] Login page: %s — CSRF token OK", next_url)

        login_data = {
            "Input.ReturnUrl": f"/connect/authorize/callback{auth_params}",
            "Input.LoginType": "FullLogin",
            "Input.Username": self.username,
            "Input.Password": self.password,
            "Input.Button": "login",
            "__RequestVerificationToken": csrf_token,
        }

        # Step 3 — submit credentials
        log.info("[Auth 3/5] POSTing credentials to: %s", next_url)
        resp = self.session.post(next_url, data=login_data, allow_redirects=False, timeout=30)
        resp.raise_for_status()
        next_url = resp.headers.get("Location")
        log.info("[Auth 3/5] After credentials, redirect: %s", next_url)

        # Step 3.5 — skip MFA-gate if present
        if next_url and "MfaGate" in next_url:
            log.info("[Auth 3.5/5] MFA gate — skipping enrollment prompt …")
            mfa_url = f"{LOGIN_URL}{next_url}" if next_url.startswith("/") else next_url
            resp = self.session.get(mfa_url, allow_redirects=False, timeout=30)
            soup = BeautifulSoup(resp.content, "html.parser")
            mfa_csrf = soup.find("input", {"name": "__RequestVerificationToken"})
            ret_url = soup.find("input", {"name": "Input.ReturnUrl"})
            mfa_data = {
                "__RequestVerificationToken": mfa_csrf.get("value") if mfa_csrf else "",
                "Input.ReturnUrl": ret_url.get("value") if ret_url
                                   else f"/connect/authorize/callback{auth_params}",
            }
            resp = self.session.post(
                f"{LOGIN_URL}/Account/MfaGate?handler=SkipMfaGate",
                data=mfa_data,
                allow_redirects=False,
                timeout=30,
            )
            next_url = resp.headers.get("Location")
            log.info("[Auth 3.5/5] After MFA skip, redirect: %s", next_url)

        # Step 4 — follow callback to get authorization code
        step4_url = f"{LOGIN_URL}{next_url}" if next_url and next_url.startswith("/") else next_url
        log.info("[Auth 4/5] Following callback: %s", step4_url)
        resp = self.session.get(step4_url, allow_redirects=False, timeout=30)
        next_url = resp.headers.get("Location")

        code = parse_qs(urlparse(next_url).query).get("code", [None])[0]
        if not code:
            raise AuthError(
                f"Authorization code not found in redirect URL: {next_url}\n"
                "Sprawdź identyfikator i hasło."
            )
        log.info("[Auth 4/5] Got authorization code.")

        # Step 5 — exchange code for access_token
        log.info("[Auth 5/5] Exchanging code for token …")
        token_data = {
            "grant_type": "authorization_code",
            "redirect_uri": oidc_redirect,
            "code": code,
            "code_verifier": code_verifier,
            "client_id": "web",
        }
        resp = self.session.post(f"{LOGIN_URL}/connect/token", data=token_data, timeout=30)
        resp.raise_for_status()
        tokens = resp.json()
        access_token = tokens.get("access_token")
        if not access_token:
            raise AuthError(f"Brak access_token w odpowiedzi serwera: {tokens}")

        self.session.headers["Authorization"] = f"Bearer {access_token}"
        log.info("Logowanie zakończone sukcesem.")

    # ------------------------------------------------------------------
    # Appointment search
    # ------------------------------------------------------------------

    def search_appointments(
        self,
        region: int,
        specialization: int,
        clinic: int = -1,
        doctor: int = -1,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        bookingtype: int = 2,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
    ) -> list[dict]:
        """
        Return a list of available appointment slots matching the criteria.

        Each item is a dict with keys:
            appointmentDate, doctorName, clinicName, specializationName, etc.
        """
        if start_date is None:
            start_date = date.today().isoformat()
        if end_date is None:
            end_date = (date.today() + timedelta(days=30)).isoformat()

        # VisitType: "Center" = stacjonarna, "Phone" = telefoniczna
        visit_type = "Phone" if bookingtype == 2 else "Center"

        params: dict = {
            "RegionIds": region,
            "SpecialtyIds": specialization,
            "Page": 1,
            "PageSize": 5000,
            "StartTime": start_date,
            "SlotSearchType": 0,
            "VisitType": visit_type,
        }
        if clinic > 0:
            params["ClinicIds"] = clinic
        if doctor > 0:
            params["DoctorIds"] = doctor

        log.debug("Parametry wyszukiwania: %s", params)

        resp = self.session.get(
            API_BASE + SEARCH_ENDPOINT,
            params=params,
            timeout=30,
        )
        resp.raise_for_status()

        items = resp.json().get("items", [])
        # Filter out slots beyond end_date
        if end_date:
            cutoff = date.fromisoformat(end_date)
            items = [
                x for x in items
                if datetime.fromisoformat(x["appointmentDate"]).date() <= cutoff
            ]
        # Filter by time range (HH:MM strings)
        if time_from:
            from datetime import time as dtime
            tf = dtime(*map(int, time_from.split(":")))
            items = [x for x in items if datetime.fromisoformat(x["appointmentDate"]).time() >= tf]
        if time_to:
            from datetime import time as dtime
            tt = dtime(*map(int, time_to.split(":")))
            items = [x for x in items if datetime.fromisoformat(x["appointmentDate"]).time() <= tt]
        log.info("Znaleziono %d termin(ów).", len(items))
        return items

    def book_appointment(self, slot: dict) -> dict:
        """Book a slot. Returns {"appointmentId": ...}."""
        booking_str = slot.get("bookingString")
        if not booking_str:
            raise ValueError("Brak bookingString w slocie — rezerwacja niemożliwa")
        # API expects {"bookingString": "<token>"}
        resp = self.session.post(
            API_BASE + BOOK_ENDPOINT,
            json={"bookingString": booking_str},
            timeout=30,
        )
        if not resp.ok:
            log.error("Błąd rezerwacji %d: %s", resp.status_code, resp.text[:500])
        resp.raise_for_status()
        return resp.json()   # {"appointmentId": 12345}

    # ------------------------------------------------------------------
    # Filter / discovery endpoints
    # ------------------------------------------------------------------

    def load_regions(self) -> list:
        """Return list of region dicts {id, name}."""
        resp = self.session.get(
            API_BASE + FILTERS_ENDPOINT,
            params={"SlotSearchType": 0},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        for key in ("regions", "availableRegions", "items"):
            if key in data:
                return data[key]
        return data if isinstance(data, list) else []

    def load_filters(
        self,
        region: int,
        bookingtype: int = 2,
        specialization: int = -1,
        clinic: int = -1,
    ) -> dict:
        """
        Return available filters for the given context.

        Returns dict with keys like 'specialties', 'clinics', 'doctors'.
        """
        params: dict = {
            "SlotSearchType": 0,
            "RegionIds": region,
        }
        if specialization > 0:
            params["SpecialtyIds"] = specialization
        if clinic > 0:
            params["ClinicIds"] = clinic

        resp = self.session.get(
            API_BASE + FILTERS_ENDPOINT, params=params, timeout=30
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def _slot_val(slot: dict, *keys: str) -> str:
    """Try multiple key patterns (flat or nested) to extract a string value."""
    for key in keys:
        if "." in key:
            obj_key, field = key.split(".", 1)
            obj = slot.get(obj_key)
            if isinstance(obj, dict):
                val = obj.get(field)
                if val:
                    return str(val)
        else:
            val = slot.get(key)
            if val is not None and val != "":
                return str(val)
    return "?"


def _slot_booking_url(slot: dict, watch: dict | None = None) -> str:
    """Return search results URL for a slot (pre-filled with date, region, specialty).

    Format: /appointments/search/results?date=...&regionId=...&specialtyIds=...
    """
    appt_date        = slot.get("appointmentDate", "")
    region_id        = (watch or {}).get("region_id", "")
    specialization   = (watch or {}).get("specialization_id", "")

    if appt_date and region_id and specialization:
        date_only = str(appt_date)[:10]
        url = (
            f"https://online24.medicover.pl/appointments/search/results"
            f"?date={date_only}"
            f"&regionId={region_id}"
            f"&specialtyIds={specialization}"
            f"&searchTypeToUse=Standard"
            f"&source=direct"
            f"&isOverbookingSearchDisabled=false"
        )
        return url

    return "https://online24.medicover.pl"


def send_email(appointments: list[dict], cfg: dict,
               slot_tokens: "dict | None" = None):
    """Send an email notification listing the available appointments.

    If slot_tokens is provided ({token: slot_dict}), each slot gets an HTML
    mailto: button so the user can trigger booking by sending that email back.
    slot_tokens keys must match appointments by _slot_key().
    """
    subject = f"Medicover: {len(appointments)} wolny(ch) termin(ów)!"

    # Build a reverse map: slot_key -> token (for button lookup)
    key_to_token: dict[str, str] = {}
    if slot_tokens:
        for tok, sl in slot_tokens.items():
            key_to_token[_slot_key(sl)] = tok

    use_html = bool(slot_tokens)

    # Group by watch name
    by_watch: dict[str, list] = {}
    for appt in appointments:
        by_watch.setdefault(appt.get("_watch_name", ""), []).append(appt)

    if use_html:
        # ---- HTML email with per-slot booking buttons ----
        html_parts: list[str] = [
            "<html><body style='font-family:sans-serif;font-size:14px'>",
        ]
        for watch_name, appts in by_watch.items():
            if watch_name:
                html_parts.append(
                    f"<h3 style='margin:16px 0 4px'>{watch_name}</h3>"
                )
            for appt in appts:
                raw_dt = appt.get("appointmentDate", "?")
                try:
                    dt = datetime.fromisoformat(raw_dt).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    dt = raw_dt
                doctor = _slot_val(appt, "doctor.name", "doctor.fullName",
                                   "doctorName", "doctor.lastName")
                clinic = _slot_val(appt, "clinic.name", "clinic.displayName", "clinicName")
                spec   = _slot_val(appt, "specialty.name", "specialty.displayName",
                                   "specializationName", "specialtyName")
                vtype  = "Telefonicznie" if appt.get("visitType") == "Phone" else "Stacjonarnie"
                token  = key_to_token.get(_slot_key(appt), "")
                btn_html = ""
                if token:
                    mailto = (
                        f"mailto:{cfg['smtp_user']}"
                        f"?subject=Medicover+rezerwacja"
                        f"&body=REZERWUJ-{token}"
                    )
                    booking_url = _slot_booking_url(appt, appt.get("_watch"))
                    # & in href must be HTML-escaped as &amp;
                    booking_url_html = booking_url.replace("&", "&amp;")
                    mailto_html = mailto.replace("&", "&amp;")
                    btn_html = (
                        f'<br><a href="{mailto_html}" '
                        f'style="display:inline-block;margin-top:6px;padding:7px 18px;'
                        f'background:#28a745;color:#fff;text-decoration:none;'
                        f'border-radius:4px;font-size:13px">'
                        f'Zarezerwuj ten termin</a>'
                        f'&nbsp;&nbsp;<a href="{booking_url_html}" '
                        f'style="display:inline-block;margin-top:6px;padding:7px 18px;'
                        f'background:#007bff;color:#fff;text-decoration:none;'
                        f'border-radius:4px;font-size:13px">'
                        f'Otwórz w aplikacji</a>'
                    )
                html_parts.append(
                    f'<div style="border:1px solid #ddd;border-radius:6px;'
                    f'padding:10px 14px;margin:8px 0">'
                    f'<b>{dt}</b> &nbsp;|&nbsp; {doctor} &nbsp;|&nbsp; '
                    f'{clinic} &nbsp;|&nbsp; {spec} &nbsp;[{vtype}]'
                    f'{btn_html}</div>'
                )
        html_parts.append(
            "<p style='color:#888;font-size:12px;margin-top:16px'>"
            "Masz 5 minut na kliknięcie przycisku. "
            "Po kliknięciu wyślij wiadomość, która się otworzy w kliencie pocztowym.</p>"
            "</body></html>"
        )
        html_body = "\n".join(html_parts)
        log.info("Wysyłam HTML email z %d przyciskami rezerwacji.", len(key_to_token))
        msg = MIMEMultipart("alternative")
        msg["From"]    = cfg["smtp_user"]
        msg["To"]      = cfg["email_to"]
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html", "utf-8"))
    else:
        # ---- Plain-text email (default) ----
        lines: list[str] = []
        for watch_name, appts in by_watch.items():
            if watch_name:
                lines.append(f"=== {watch_name} ===")
            for appt in appts:
                raw_dt = appt.get("appointmentDate", "?")
                try:
                    dt = datetime.fromisoformat(raw_dt).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    dt = raw_dt
                doctor = _slot_val(appt, "doctor.name", "doctor.fullName",
                                   "doctorName", "doctor.lastName")
                clinic = _slot_val(appt, "clinic.name", "clinic.displayName", "clinicName")
                spec   = _slot_val(appt, "specialty.name", "specialty.displayName",
                                   "specializationName", "specialtyName")
                vtype  = "Telefonicznie" if appt.get("visitType") == "Phone" else "Stacjonarnie"
                url    = _slot_booking_url(appt, appt.get("_watch"))
                lines.append(
                    f"  {dt}  |  {doctor}  |  {clinic}  |  {spec}  [{vtype}]\n"
                    f"  Zarezerwuj: {url}"
                )
            lines.append("")
        body = "\n".join(lines).rstrip()
        log.info("Treść powiadomienia:\n%s", body)
        msg = MIMEMultipart()
        msg["From"]    = cfg["smtp_user"]
        msg["To"]      = cfg["email_to"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

    host = cfg["smtp_host"]
    port = int(cfg.get("smtp_port", 587))

    log.info("Wysyłam email do %s przez %s:%d …", cfg["email_to"], host, port)
    if port == 465:
        # SSL/TLS bezpośrednio (np. Interia: poczta.interia.pl:465)
        with smtplib.SMTP_SSL(host, port, timeout=30) as server:
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
    else:
        # STARTTLS (np. Gmail: smtp.gmail.com:587)
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())

    log.info("Email wysłany pomyślnie.")


# ---------------------------------------------------------------------------
# Discovery helper
# ---------------------------------------------------------------------------

def run_discover(args):
    """Print available regions / specializations / clinics / doctors."""
    username = _require_env("MEDICOVER_USER")
    password = _require_env("MEDICOVER_PASS")

    sess = MedicoverSession(username, password)
    sess.log_in()

    if args.region is None:
        print("\n=== Regiony ===")
        for r in sess.load_regions():
            print(f"  id={r.get('id', r.get('value', '?')):>6}  {r.get('text', r.get('name', r))}")
        return

    filters = sess.load_filters(
        region=args.region,
        bookingtype=args.bookingtype,
        specialization=args.specialization if args.specialization else -1,
        clinic=args.clinic if args.clinic else -1,
    )

    if args.specialization is None:
        # New API returns "specialties", old returned "specializations"
        spec_key = "specialties" if "specialties" in filters else "specializations"
        _print_list(filters, spec_key, "Specjalizacje")
    elif args.clinic is None:
        _print_list(filters, "clinics", "Placówki")
    else:
        _print_list(filters, "doctors", "Lekarze")


def _print_list(data: dict, key: str, label: str):
    items = data.get(key, [])
    if not items:
        # Try to print the whole response if the expected key is missing
        print(f"\n[Klucz '{key}' nie znaleziony. Odpowiedź API:]")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
    print(f"\n=== {label} ===")
    for item in items:
        item_id = item.get("id", item.get("value", "?"))
        item_name = item.get("text", item.get("name", str(item)))
        print(f"  id={item_id:>6}  {item_name}")


# ---------------------------------------------------------------------------
# Booking via email reply (IMAP polling)
# ---------------------------------------------------------------------------

def wait_for_slot_signal(cfg: dict, slot_tokens: dict) -> "str | None":
    """
    Poll IMAP inbox every IMAP_POLL_S seconds for up to BOOKING_WAIT_S seconds.
    Returns the slot token whose code was found in an incoming message, or None.

    slot_tokens: {token_str: slot_dict}
    Signal message must contain the token string anywhere in the body.
    """
    import imaplib
    import email as email_lib

    today_str = date.today().strftime("%d-%b-%Y")
    deadline = time.time() + BOOKING_WAIT_S
    log.info("IMAP: łączę z %s:%d …", IMAP_HOST, IMAP_PORT)

    try:
        with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
            imap.login(cfg["smtp_user"], cfg["smtp_pass"])
            imap.select("INBOX")
            log.info("IMAP: zalogowano. Czekam na sygnał (tokeny: %s)…",
                     list(slot_tokens.keys()))
            while time.time() < deadline:
                imap.noop()   # keep-alive
                for token in slot_tokens:
                    status, msgs = imap.search(
                        None,
                        f'(BODY "{token}" SINCE "{today_str}")',
                    )
                    if status == "OK" and msgs[0]:
                        log.info("IMAP: wykryto sygnał dla tokenu %s", token)
                        return token
                time.sleep(IMAP_POLL_S)
            log.info("IMAP: timeout — brak sygnału w ciągu %ds.", BOOKING_WAIT_S)
    except Exception as e:
        log.warning("IMAP: błąd podczas oczekiwania na sygnał: %s", e)
    return None


def send_booking_confirmation(slot: dict, cfg: dict, appt_id: int) -> None:
    """Send a confirmation email after successful booking."""
    raw_dt = slot.get("appointmentDate", "?")
    try:
        dt = datetime.fromisoformat(raw_dt).strftime("%Y-%m-%d %H:%M")
    except Exception:
        dt = raw_dt
    doctor  = _slot_val(slot, "doctor.name", "doctor.fullName", "doctorName")
    clinic  = _slot_val(slot, "clinic.name", "clinic.displayName", "clinicName")
    spec    = _slot_val(slot, "specialty.name", "specialty.displayName", "specializationName")
    watch_name = slot.get("_watch_name", "")

    subject = f"Zarezerwowano wizytę! {'(' + watch_name + ') ' if watch_name else ''}ID: {appt_id}"
    body = (
        f"Wizyta zarezerwowana pomyślnie.\n\n"
        f"Data:        {dt}\n"
        f"Lekarz:      {doctor}\n"
        f"Placówka:    {clinic}\n"
        f"Specjalność: {spec}\n"
        f"ID rezerwacji: {appt_id}\n\n"
        f"Zarządzaj wizytami: https://online24.medicover.pl\n"
    )

    msg = MIMEMultipart()
    msg["From"]    = cfg["smtp_user"]
    msg["To"]      = cfg["email_to"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    host = cfg["smtp_host"]
    port = int(cfg.get("smtp_port", 465))
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=30) as server:
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo(); server.starttls()
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
    log.info("Email potwierdzający wysłany.")


# ---------------------------------------------------------------------------
# Notified-slots deduplication
# ---------------------------------------------------------------------------

NOTIFIED_FILE = "notified.json"


def _slot_key(slot: dict) -> str:
    """Stable unique identifier for a slot (does not use bookingString)."""
    doctor_id = (slot.get("doctor") or {}).get("id", "?")
    appt_date = slot.get("appointmentDate", "")[:19]  # strip timezone offset
    return f"{doctor_id}_{appt_date}"


def _load_notified() -> set:
    """Return set of slot keys already notified today."""
    today = date.today().isoformat()
    try:
        with open(NOTIFIED_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get(today, []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _save_notified(new_keys: set) -> None:
    """Merge new_keys into today's notified list; drop older dates."""
    today = date.today().isoformat()
    try:
        with open(NOTIFIED_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data = {today: list(set(data.get(today, [])) | new_keys)}
    with open(NOTIFIED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _git_push_notified() -> None:
    """Commit and push notified.json back to the repo (only in GitHub Actions)."""
    import subprocess
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    try:
        subprocess.run(["git", "add", NOTIFIED_FILE], check=True)
        diff = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if diff.returncode == 0:
            log.info("notified.json bez zmian — pomijam commit.")
            return
        subprocess.run(
            ["git", "commit", "-m", "chore: update notified slots [skip ci]"],
            check=True,
        )
        subprocess.run(["git", "pull", "--rebase", "--autostash"], check=True)
        subprocess.run(["git", "push"], check=True)
        log.info("notified.json wypchnięty do repozytorium.")
    except Exception as e:
        log.warning("Nie udało się wypchnąć notified.json: %s", e)


# ---------------------------------------------------------------------------
# Main monitoring logic
# ---------------------------------------------------------------------------

def run_monitor(args):
    """Check for appointments and send email if any are found."""
    username = _require_env("MEDICOVER_USER")
    password = _require_env("MEDICOVER_PASS")

    email_cfg = {
        "email_to": _require_env("EMAIL_TO"),
        "smtp_host": _require_env("SMTP_HOST"),
        "smtp_port": _cfg("SMTP_PORT", "465"),
        "smtp_user": _require_env("SMTP_USER"),
        "smtp_pass": _require_env("SMTP_PASS"),
    }

    cfg_file = _load_config_file()
    watches = cfg_file.get("watches", [])

    if not watches:
        # Legacy flat config (env vars or flat config.yml keys)
        watches = [{
            "name": "",
            "region_id":         int(_require_env("REGION_ID")),
            "specialization_id": int(_require_env("SPECIALIZATION_ID")),
            "clinic_id":         int(_cfg("CLINIC_ID", "-1")),
            "doctor_id":         int(_cfg("DOCTOR_ID", "-1")),
            "booking_type":      int(_cfg("BOOKING_TYPE", "2")),
            "days_ahead":        int(_cfg("DAYS_AHEAD", "30")),
        }]

    sess = MedicoverSession(username, password)
    sess.log_in()

    notified = _load_notified()
    new_notified: set = set()

    # Collect slots from all booking_reply watches into one combined email
    all_booking_slot_tokens: dict = {}   # token -> slot

    for watch in watches:
        days = int(watch.get("days_ahead", 30))
        end_date = (date.today() + timedelta(days=days)).isoformat()
        watch_name = watch.get("name", "")
        log.info("Sprawdzam czujkę: %s", watch_name or "(bez nazwy)")
        appts = sess.search_appointments(
            region=int(watch["region_id"]),
            specialization=int(watch["specialization_id"]),
            clinic=int(watch.get("clinic_id", -1)),
            doctor=int(watch.get("doctor_id", -1)),
            end_date=end_date,
            bookingtype=int(watch.get("booking_type", 2)),
            time_from=watch.get("time_from") or None,
            time_to=watch.get("time_to") or None,
        )
        if not appts:
            log.info("Brak wolnych terminów dla czujki: %s", watch_name or "(bez nazwy)")
            continue
        # Filter out already-notified slots
        appts = [a for a in appts if _slot_key(a) not in notified]
        if not appts:
            log.info("Wszystkie terminy dla czujki '%s' już zgłoszone dziś — pomijam.", watch_name or "(bez nazwy)")
            continue
        for a in appts:
            a["_watch_name"] = watch_name
            a["_watch"] = watch

        new_notified |= {_slot_key(a) for a in appts}

        # Use watch-specific email_to if defined, otherwise fall back to global
        watch_email_cfg = dict(email_cfg)
        if watch.get("email_to"):
            watch_email_cfg["email_to"] = watch["email_to"]

        # All watches always get booking buttons — accumulate for one combined email
        slot_tokens = {str(uuid.uuid4())[:8].upper(): a for a in appts}
        all_booking_slot_tokens.update(slot_tokens)

    # Send one combined email for all booking_reply slots, then wait once
    if all_booking_slot_tokens:
        all_booking_appts = list(all_booking_slot_tokens.values())
        send_email(all_booking_appts, email_cfg, slot_tokens=all_booking_slot_tokens)
        log.info("Czekam %ds na sygnał rezerwacji (tokeny: %s)…",
                 BOOKING_WAIT_S, list(all_booking_slot_tokens.keys()))
        chosen = wait_for_slot_signal(email_cfg, all_booking_slot_tokens)
        if chosen:
            slot_to_book = all_booking_slot_tokens[chosen]
            log.info("Rezerwuję termin z tokenem %s …", chosen)
            try:
                result = sess.book_appointment(slot_to_book)
                appt_id = result.get("appointmentId")
                log.info("Zarezerwowano! appointmentId=%s", appt_id)
                send_booking_confirmation(slot_to_book, email_cfg, appt_id)
            except Exception as e:
                log.error("Błąd rezerwacji: %s", e)
        else:
            log.info("Brak sygnału w ciągu %ds — termin nie zarezerwowany.", BOOKING_WAIT_S)

    if new_notified:
        _save_notified(new_notified)
        _git_push_notified()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _load_config_file(path: str = "config.yml") -> dict:
    """
    Load non-secret configuration from config.yml if it exists.
    Environment variables always take priority over file values.
    """
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Module-level config file cache
_cfg_file: dict | None = None


def _cfg(name: str, default: str | None = None) -> str | None:
    """Return env var value, falling back to config.yml, then default."""
    global _cfg_file
    if _cfg_file is None:
        _cfg_file = _load_config_file()
    env_val = os.environ.get(name)
    if env_val:
        return env_val
    file_val = _cfg_file.get(name)
    if file_val is not None:
        return str(file_val)
    return default


def _require_env(name: str) -> str:
    value = _cfg(name)
    if not value:
        log.error(
            "Brak wartości dla '%s' — ustaw zmienną środowiskową lub wpisz do config.yml",
            name,
        )
        sys.exit(1)
    return value


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitorowanie wolnych wizyt w Medicover",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # --- monitor (default) ---
    sub.add_parser(
        "monitor",
        help="Sprawdź wolne terminy i wyślij email (domyślne)",
    )

    # --- discover ---
    disc = sub.add_parser(
        "discover",
        help="Odkryj dostępne regiony / specjalizacje / placówki / lekarzy",
    )
    disc.add_argument("--region", type=int, default=None, help="ID regionu")
    disc.add_argument("--specialization", type=int, default=None, help="ID specjalizacji")
    disc.add_argument("--clinic", type=int, default=None, help="ID placówki")
    disc.add_argument(
        "--bookingtype",
        type=int,
        default=2,
        help="Typ wizyty: 1=stacjonarna, 2=telefoniczna (domyślnie 2)",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "discover":
        run_discover(args)
    else:
        # Default: run monitor
        run_monitor(args)


if __name__ == "__main__":
    main()
