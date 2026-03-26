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
BOOKING_WAIT_S = int(os.environ.get("BOOKING_WAIT_SECONDS", "240"))  # override lokalnie
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

SESSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "session.json")


class MedicoverSession:
    """Handles authentication and API calls against online24.medicover.pl."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    # ------------------------------------------------------------------
    # Session persistence
    # ------------------------------------------------------------------

    def save_session(self) -> None:
        """Save session cookies to disk for reuse between runs."""
        cookies = {c.name: c.value for c in self.session.cookies}
        data = {"cookies": cookies, "saved_at": time.time()}
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
        log.info("Sesja zapisana do %s (%d cookies).", SESSION_FILE, len(cookies))

    def load_session(self) -> bool:
        """Load saved session cookies. Returns True if session is still valid."""
        if not os.path.exists(SESSION_FILE):
            return False
        try:
            with open(SESSION_FILE, encoding="utf-8") as f:
                data = json.load(f)
            age_h = (time.time() - data.get("saved_at", 0)) / 3600
            if age_h > 4:
                log.info("Zapisana sesja za stara (%.1fh) — pomijam.", age_h)
                return False
            for name, value in data.get("cookies", {}).items():
                self.session.cookies.set(name, value)
            log.info("Wczytano sesję z pliku (%.1fh temu, %d cookies).",
                     age_h, len(data.get("cookies", {})))
        except Exception as e:
            log.warning("Nie udało się wczytać sesji: %s", e)
            return False
        # Verify session is still alive with a lightweight API call
        try:
            resp = self.session.get(
                API_BASE + FILTERS_ENDPOINT,
                params={"RegionIds": 1, "SlotSearchType": 0},
                timeout=15,
            )
            if resp.ok:
                log.info("Zapisana sesja aktywna — pomijam logowanie.")
                return True
            log.info("Zapisana sesja wygasła (HTTP %d) — loguję ponownie.", resp.status_code)
        except Exception as e:
            log.warning("Nie udało się zweryfikować sesji: %s", e)
        return False

    # ------------------------------------------------------------------
    # PKCE helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pkce_challenge(verifier: str) -> str:
        """Return base64url(SHA-256(verifier)) with no padding."""
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    # ------------------------------------------------------------------
    # MFA — fetch OTP code from IMAP inbox
    # ------------------------------------------------------------------

    def _fetch_mfa_code_from_imap(self, timeout_s: int = 120, known_ids: "set | None" = None) -> "str | None":
        """Poll IMAP for Medicover MFA verification code email.

        Looks for an email from medicover@medicover.pl with a 6-digit code.
        known_ids: set of IMAP message IDs to skip (captured before code was triggered).
        Returns the code string or None if not found within timeout.
        """
        import imaplib
        import email as email_lib
        import re

        imap_host = os.environ.get("IMAP_HOST", os.environ.get("SMTP_HOST", ""))
        imap_user = os.environ.get("SMTP_USER", "")
        imap_pass = os.environ.get("SMTP_PASS", "")

        if not all([imap_host, imap_user, imap_pass]):
            log.error("Brak danych IMAP (SMTP_HOST/SMTP_USER/SMTP_PASS) — nie mogę pobrać kodu MFA.")
            return None

        today_str = date.today().strftime("%d-%b-%Y")
        deadline = time.time() + timeout_s
        poll_interval = 5

        try:
            with imaplib.IMAP4_SSL(imap_host, 993) as imap:
                imap.login(imap_user, imap_pass)
                imap.select("INBOX")

                # Use pre-captured known_ids if provided, otherwise snapshot now
                if known_ids is None:
                    status, msgs = imap.search(
                        None, f'(FROM "medicover" SINCE "{today_str}")',
                    )
                    known_ids = set(msgs[0].split()) if status == "OK" and msgs[0] else set()
                log.info("IMAP: czekam na NOWY kod MFA (timeout %ds, istniejących: %d) …",
                         timeout_s, len(known_ids))

                while time.time() < deadline:
                    imap.noop()
                    status, msgs = imap.search(
                        None, f'(FROM "medicover" SINCE "{today_str}")',
                    )
                    if status == "OK" and msgs[0]:
                        msg_ids = msgs[0].split()
                        new_ids = [m for m in msg_ids if m not in known_ids]
                        for mid in reversed(new_ids):
                            _, msg_data = imap.fetch(mid, "(RFC822)")
                            if not msg_data or not msg_data[0]:
                                continue
                            raw = msg_data[0][1]
                            msg = email_lib.message_from_bytes(raw)
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    ct = part.get_content_type()
                                    if ct in ("text/plain", "text/html"):
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            body += payload.decode("utf-8", errors="replace")
                            else:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    body = payload.decode("utf-8", errors="replace")

                            match = re.search(r'\b(\d{6})\b', body)
                            if match and "weryfikacyjny" in body.lower():
                                return match.group(1)
                    time.sleep(poll_interval)

                log.warning("IMAP: timeout — nie znaleziono kodu MFA.")
        except Exception as e:
            log.error("IMAP: błąd podczas pobierania kodu MFA: %s", e)
        return None

    def _exchange_token(self, code: str, code_verifier: str, redirect_uri: str):
        """Exchange authorization code for access_token (Step 5)."""
        token_data = {
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
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
        authorize_url = f"{LOGIN_URL}/connect/authorize{auth_params}"
        log.info("[Auth 1/5] GET %s/connect/authorize …", LOGIN_URL)
        resp = self.session.get(
            authorize_url,
            allow_redirects=False,
            timeout=30,
        )
        next_url = resp.headers.get("Location")
        log.info("[Auth 1/5] Redirect to: %s", next_url)
        if not next_url:
            raise AuthError(
                f"Brak przekierowania w kroku 1 (status {resp.status_code}). "
                "Możliwe rate-limiting (429) — odczekaj kilka minut."
            )

        # Check if SSO session is still valid (redirect goes to callback, not login page)
        if next_url and "code=" in next_url:
            log.info("[Auth 1/5] SSO sesja ważna — pomijam logowanie i MFA.")
            step4_url = next_url
            # Jump directly to step 4 (extract auth code)
            if step4_url.startswith("/"):
                step4_url = f"{LOGIN_URL}{step4_url}"
            elif step4_url.startswith("https://online24"):
                # Already a full callback URL with code — parse it directly
        
                parsed = urlparse(step4_url)
                qs = parse_qs(parsed.query)
                auth_code = qs.get("code", [None])[0]
                if auth_code:
                    log.info("[Auth 5/5] Exchanging code for token …")
                    self._exchange_token(auth_code, code_verifier, oidc_redirect)
                    log.info("Logowanie zakończone sukcesem.")
                    self.save_session()
                    return
            resp = self.session.get(step4_url, allow_redirects=False, timeout=30)
            next_url = resp.headers.get("Location")
            if next_url and "code=" in next_url:
        
                parsed = urlparse(next_url)
                qs = parse_qs(parsed.query)
                auth_code = qs.get("code", [None])[0]
                if auth_code:
                    log.info("[Auth 5/5] Exchanging code for token …")
                    self._exchange_token(auth_code, code_verifier, oidc_redirect)
                    log.info("Logowanie zakończone sukcesem.")
                    self.save_session()
                    return

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
        if not next_url:
            # No redirect — login failed; check response for error message
            soup3 = BeautifulSoup(resp.content, "html.parser")
            err_div = soup3.find("div", class_="validation-summary-errors") or soup3.find("div", class_="text-danger")
            err_msg = err_div.get_text(strip=True) if err_div else ""
            log.error("[Auth 3/5] Brak przekierowania po logowaniu. Status: %d. Błąd na stronie: %s",
                      resp.status_code, err_msg or "(brak)")
            raise AuthError(
                f"Logowanie nieudane — serwer nie przekierował (status {resp.status_code}). "
                f"{('Komunikat: ' + err_msg) if err_msg else 'Sprawdź login i hasło lub spróbuj później.'}"
            )

        # Step 3.5 — handle MFA (code verification or enrollment skip)
        if next_url and ("MfaGate" in next_url or "Mfa" in next_url):
            mfa_url = f"{LOGIN_URL}{next_url}" if next_url.startswith("/") else next_url
            log.info("[Auth 3.5/5] MFA detected: %s", mfa_url)
            resp = self.session.get(mfa_url, allow_redirects=False, timeout=30)
            soup = BeautifulSoup(resp.content, "html.parser")

            # Check if this is a code-entry page (OTP via email)
            has_mfa_code = soup.find("input", {"name": "Input.MfaCode"})

            if has_mfa_code:
                # --- MFA code verification ---
                # Snapshot IMAP state BEFORE triggering code send
                import imaplib as _imaplib
                _imap_host = os.environ.get("IMAP_HOST", os.environ.get("SMTP_HOST", ""))
                _imap_user = os.environ.get("SMTP_USER", "")
                _imap_pass = os.environ.get("SMTP_PASS", "")
                _today = date.today().strftime("%d-%b-%Y")
                _pre_ids = set()
                try:
                    with _imaplib.IMAP4_SSL(_imap_host, 993) as _im:
                        _im.login(_imap_user, _imap_pass)
                        _im.select("INBOX")
                        _st, _ms = _im.search(None, f'(FROM "medicover" SINCE "{_today}")')
                        if _st == "OK" and _ms[0]:
                            _pre_ids = set(_ms[0].split())
                    log.info("[Auth 3.5/5] IMAP snapshot: %d istniejących emaili", len(_pre_ids))
                except Exception as _e:
                    log.warning("[Auth 3.5/5] Nie udało się zrobić IMAP snapshot: %s", _e)

                # Step 1: trigger code sending (browser does this via JS on page load)
                form = soup.find("form")
                form_action = form.get("action", "") if form else ""
                if form_action and not form_action.startswith("http"):
                    form_action = f"{LOGIN_URL}{form_action}"
                if not form_action:
                    form_action = mfa_url
                if "Operation=" not in form_action:
                    form_action += "&Operation=SIGN_IN" if "?" in form_action else "?Operation=SIGN_IN"

                resend_data = {}
                for inp in (form.find_all("input") if form else []):
                    name = inp.get("name")
                    if name:
                        resend_data[name] = inp.get("value", "")
                resend_data["Input.Button"] = "resend"
                log.info("[Auth 3.5/5] Wysyłam żądanie kodu MFA (resend) …")
                resend_resp = self.session.post(
                    form_action, data=resend_data,
                    allow_redirects=False, timeout=30,
                )
                log.info("[Auth 3.5/5] Resend response: status=%d", resend_resp.status_code)

                # Re-parse the form after resend (new CSRF token, new MfaCodeId)
                if resend_resp.status_code == 200:
                    soup = BeautifulSoup(resend_resp.content, "html.parser")
                    form = soup.find("form")

                # Step 2: wait for code via IMAP
                log.info("[Auth 3.5/5] MFA wymaga kodu — pobieram z IMAP …")
                otp = self._fetch_mfa_code_from_imap(known_ids=_pre_ids)
                if not otp:
                    raise AuthError("Nie udało się pobrać kodu MFA z emaila w ciągu 120s.")

                log.info("[Auth 3.5/5] Kod MFA: %s — wysyłam …", otp)

                # Collect ALL hidden form fields (re-parsed after resend)
                form_action_confirm = form.get("action", "") if form else ""
                if form_action_confirm and not form_action_confirm.startswith("http"):
                    form_action_confirm = f"{LOGIN_URL}{form_action_confirm}"
                if not form_action_confirm:
                    form_action_confirm = mfa_url
                if "Operation=" not in form_action_confirm:
                    form_action_confirm += "&Operation=SIGN_IN" if "?" in form_action_confirm else "?Operation=SIGN_IN"

                mfa_data = {}
                for inp in (form.find_all("input") if form else []):
                    name = inp.get("name")
                    if name:
                        mfa_data[name] = inp.get("value", "")
                # Fill in the code and submit button
                mfa_data["Input.MfaCode"] = otp
                mfa_data["Input.Button"] = "confirm"
                mfa_data["Input.IsTrustedDevice"] = "True"
                mfa_data["Input.DeviceName"] = "Chrome"

                # Debug: log what we're sending
                for k, v in mfa_data.items():
                    log.info("[MFA POST] %s = %s", k, str(v)[:80] if k != "__RequestVerificationToken" else "***")
                log.info("[MFA POST] -> %s", form_action_confirm)

                resp = self.session.post(
                    form_action_confirm, data=mfa_data,
                    allow_redirects=False, timeout=30,
                )
                next_url = resp.headers.get("Location")
                log.info("[Auth 3.5/5] After MFA code submit: status=%d redirect=%s",
                         resp.status_code, next_url)
                if not next_url and resp.status_code == 200:
                    err_soup = BeautifulSoup(resp.content, "html.parser")
                    # Search broadly for any error/validation messages
                    for sel in ["span.text-danger", "div.validation-summary-errors",
                                ".field-validation-error", "[data-valmsg-summary]",
                                ".alert-danger", ".error-message"]:
                        err_el = err_soup.select_one(sel)
                        if err_el and err_el.get_text(strip=True):
                            log.error("[Auth 3.5/5] MFA error (%s): %s", sel, err_el.get_text(strip=True))
                    # Also check if MfaCode field has new MfaCodeId (form re-rendered = code rejected)
                    new_code_id = err_soup.find("input", {"name": "Input.MfaCodeId"})
                    if new_code_id:
                        log.warning("[Auth 3.5/5] Formularz MFA odesłany ponownie — kod odrzucony lub wygasł.")

                # Follow any intermediate redirects (e.g. MfaGate -> callback)
                while next_url and "callback" not in next_url and next_url != "/":
                    step_url = f"{LOGIN_URL}{next_url}" if next_url.startswith("/") else next_url
                    resp = self.session.get(step_url, allow_redirects=False, timeout=30)
                    next_url = resp.headers.get("Location")
                    log.info("[Auth 3.5/5] Following redirect: %s", next_url)
            else:
                # --- MFA enrollment skip (legacy) ---
                log.info("[Auth 3.5/5] MFA gate — skipping enrollment prompt …")
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

            # If MFA redirected to homepage instead of callback, re-trigger authorize
            if not next_url or next_url == "/" or "callback" not in next_url:
                log.info("[Auth 3.5/5] MFA redirect lost callback — re-triggering authorize …")
                resp = self.session.get(authorize_url, allow_redirects=False, timeout=30)
                next_url = resp.headers.get("Location")
                log.info("[Auth 3.5/5] Re-authorize redirect: %s", next_url)

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
        self._exchange_token(code, code_verifier, oidc_redirect)
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

        for attempt in range(4):
            resp = self.session.get(
                API_BASE + SEARCH_ENDPOINT,
                params=params,
                timeout=30,
            )
            if resp.status_code == 429:
                wait = 30 * (attempt + 1)  # 30s, 60s, 90s, 120s
                log.warning("429 Too Many Requests — czekam %ds przed ponowną próbą…", wait)
                time.sleep(wait)
                continue
            break
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
        visit_type = "Phone" if bookingtype == 2 else "Center"
        params: dict = {
            "SlotSearchType": 0,
            "RegionIds": region,
            "VisitType": visit_type,
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
            "Masz 4 minuty na kliknięcie przycisku. "
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


def send_booking_failure(slot: dict, cfg: dict, error: Exception) -> None:
    """Send an email notification after a failed booking attempt."""
    raw_dt = slot.get("appointmentDate", "?")
    try:
        dt = datetime.fromisoformat(raw_dt).strftime("%Y-%m-%d %H:%M")
    except Exception:
        dt = raw_dt
    doctor     = _slot_val(slot, "doctor.name", "doctor.fullName", "doctorName")
    clinic     = _slot_val(slot, "clinic.name", "clinic.displayName", "clinicName")
    spec       = _slot_val(slot, "specialty.name", "specialty.displayName", "specializationName")
    watch_name = slot.get("_watch_name", "")

    error_str  = str(error)
    if "futureLimitReached" in error_str:
        reason = "Osiągnięto limit przyszłych wizyt tego specjalisty. Odwołaj jedną z istniejących wizyt i spróbuj ponownie."
    elif "409" in error_str:
        reason = f"Konflikt rezerwacji (409). Termin mógł zostać zajęty przez kogoś innego."
    else:
        reason = error_str

    subject = f"BŁĄD rezerwacji! {'(' + watch_name + ') ' if watch_name else ''}{dt}"
    body = (
        f"Rezerwacja nie powiodła się.\n\n"
        f"Data:        {dt}\n"
        f"Lekarz:      {doctor}\n"
        f"Placówka:    {clinic}\n"
        f"Specjalność: {spec}\n\n"
        f"Powód: {reason}\n\n"
        f"Zarządzaj wizytami: https://online24.medicover.pl\n"
    )

    msg = MIMEMultipart()
    msg["From"]    = cfg["smtp_user"]
    msg["To"]      = cfg["email_to"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    host = cfg["smtp_host"]
    port = int(cfg.get("smtp_port", 465))
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=30) as server:
                server.login(cfg["smtp_user"], cfg["smtp_pass"])
                server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=30) as server:
                server.ehlo(); server.starttls()
                server.login(cfg["smtp_user"], cfg["smtp_pass"])
                server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
        log.info("Email o błędzie rezerwacji wysłany.")
    except Exception as mail_err:
        log.error("Nie udało się wysłać emaila o błędzie: %s", mail_err)


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


def _git_push_state() -> None:
    """Commit and push notified.json + session.json back to the repo (GitHub Actions only)."""
    import subprocess
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    try:
        files = [NOTIFIED_FILE]
        if os.path.exists(SESSION_FILE):
            files.append(SESSION_FILE)
        subprocess.run(["git", "add"] + files, check=True)
        diff = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if diff.returncode == 0:
            log.info("Brak zmian w plikach stanu — pomijam commit.")
            return
        subprocess.run(
            ["git", "commit", "-m", "chore: update notified slots [skip ci]"],
            check=True,
        )
        subprocess.run(["git", "pull", "--rebase", "--autostash"], check=True)
        subprocess.run(["git", "push"], check=True)
        log.info("Pliki stanu wypchnięte do repozytorium.")
    except Exception as e:
        log.warning("Nie udało się wypchnąć plików stanu: %s", e)


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
    if not sess.load_session():
        sess.log_in()
        sess.save_session()

    notified = _load_notified()
    new_notified: set = set()

    # Collect slots from all watches
    all_booking_slot_tokens: dict = {}   # token -> slot
    slots_by_email: dict = {}            # email_to -> {token -> slot}

    for i, watch in enumerate(watches):
        if i > 0:
            time.sleep(3)  # pauza między czujkami — unikamy 429
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

        # Group slots by target email address
        target_email = watch.get("email_to") or email_cfg["email_to"]
        slot_tokens = {str(uuid.uuid4())[:8].upper(): a for a in appts}
        all_booking_slot_tokens.update(slot_tokens)
        slots_by_email.setdefault(target_email, {}).update(slot_tokens)

    # Send separate email per recipient, then wait once for IMAP signal
    for target_email, tokens in slots_by_email.items():
        cfg_for_send = dict(email_cfg)
        cfg_for_send["email_to"] = target_email
        send_email(list(tokens.values()), cfg_for_send, slot_tokens=tokens)
        log.info("Email wysłany do %s (%d terminów).", target_email, len(tokens))

    if all_booking_slot_tokens:
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
                send_booking_failure(slot_to_book, email_cfg, e)
        else:
            log.info("Brak sygnału w ciągu %ds — termin nie zarezerwowany.", BOOKING_WAIT_S)

    if new_notified:
        _save_notified(new_notified)
    _git_push_state()  # always push session.json + notified.json


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
