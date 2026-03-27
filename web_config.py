#!/usr/bin/env python3
"""
Medicover Monitor — lokalny konfigurator webowy

Uruchom: python web_config.py
Otwórz:  http://localhost:5000

Umożliwia:
  1. Logowanie do Medicover identyfikatorem
  2. Wybór regionu / specjalizacji / placówki / lekarza (kaskadowe dropdowny)
  3. Zapis wybranych parametrów do config.yml (bez haseł)
  4. Wypchnięcie config.yml do git (git add + commit + push)
"""

import logging
import os
import sys
import json
import subprocess

import yaml
from flask import Flask, jsonify, request, render_template_string

log = logging.getLogger(__name__)

# Dodaj katalog bieżący do ścieżki, żeby importować monitor.py
sys.path.insert(0, os.path.dirname(__file__))
from monitor import MedicoverSession, AuthError

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Stan sesji (single-user, lokalny)
# ---------------------------------------------------------------------------

_session: MedicoverSession | None = None


def _get_session() -> MedicoverSession:
    if _session is None:
        raise RuntimeError("Nie zalogowano do Medicover")
    return _session


# ---------------------------------------------------------------------------
# HTML (wbudowany)
# ---------------------------------------------------------------------------

HTML = r"""
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Medicover Monitor — Konfigurator</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #f0f4f8;
    color: #1a202c;
    padding: 2rem;
  }
  h1 { font-size: 1.5rem; font-weight: 700; color: #2d3748; margin-bottom: 1.5rem; }
  .card {
    background: #fff;
    border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
    padding: 1.5rem;
    margin-bottom: 1.25rem;
  }
  .card h2 {
    font-size: 1rem;
    font-weight: 600;
    color: #4a5568;
    margin-bottom: 1rem;
    padding-bottom: .5rem;
    border-bottom: 1px solid #e2e8f0;
  }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .field { display: flex; flex-direction: column; gap: .3rem; flex: 1; min-width: 180px; }
  label { font-size: .8rem; font-weight: 600; color: #718096; text-transform: uppercase; letter-spacing: .04em; }
  input, select {
    padding: .5rem .75rem;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    font-size: .95rem;
    background: #fff;
    color: #2d3748;
    width: 100%;
  }
  input:focus, select:focus { outline: 2px solid #4299e1; border-color: transparent; }
  select:disabled { background: #f7fafc; color: #a0aec0; }
  .radio-group { display: flex; gap: 1rem; align-items: center; padding-top: .4rem; }
  .radio-group label { text-transform: none; font-size: .95rem; font-weight: 400; display: flex; align-items: center; gap: .4rem; cursor: pointer; }
  .actions { display: flex; gap: 1rem; flex-wrap: wrap; }
  .watch-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: .6rem .85rem; border: 1px solid #e2e8f0; border-radius: 8px;
    margin-bottom: .5rem; background: #f7fafc;
  }
  .watch-item .watch-name { font-weight: 600; font-size: .95rem; color: #2d3748; }
  .watch-item .watch-detail { font-size: .8rem; color: #718096; margin-top: .1rem; }
  .watch-empty { color: #a0aec0; font-size: .9rem; padding: .5rem 0; }
  .btn-danger { background: #e53e3e; color: #fff; }
  .btn-danger:hover:not(:disabled) { background: #c53030; }
  .btn-sm { padding: .3rem .75rem; font-size: .85rem; }
  button {
    padding: .55rem 1.25rem;
    border: none;
    border-radius: 6px;
    font-size: .95rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity .15s;
  }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .btn-primary { background: #4299e1; color: #fff; }
  .btn-primary:hover:not(:disabled) { background: #3182ce; }
  .btn-success { background: #48bb78; color: #fff; }
  .btn-success:hover:not(:disabled) { background: #38a169; }
  .btn-git { background: #2d3748; color: #fff; }
  .btn-git:hover:not(:disabled) { background: #1a202c; }
  #status {
    margin-top: 1rem;
    padding: .75rem 1rem;
    border-radius: 6px;
    font-size: .9rem;
    display: none;
  }
  .status-ok  { background: #f0fff4; border: 1px solid #9ae6b4; color: #276749; }
  .status-err { background: #fff5f5; border: 1px solid #feb2b2; color: #c53030; }
  .status-inf { background: #ebf8ff; border: 1px solid #90cdf4; color: #2b6cb0; }
  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin .6s linear infinite; vertical-align: middle; margin-right: .4rem; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .note { font-size: .8rem; color: #718096; margin-top: .4rem; }
</style>
</head>
<body>
<h1>Medicover Monitor — Konfigurator</h1>

<!-- 0. Wybór konta / repo -->
<div class="card">
  <h2>0. Konto Medicover</h2>
  <div class="row">
    <div class="field">
      <label>Repozytorium</label>
      <select id="sel-repo" onchange="switchRepo()">
      </select>
    </div>
    <div class="field">
      <label>Status</label>
      <div id="repo-status" style="padding-top:.4rem;font-size:.9rem;color:#718096;">—</div>
    </div>
  </div>
</div>

<!-- 1. Logowanie -->
<div class="card">
  <h2>1. Logowanie do Medicover</h2>
  <div class="row">
    <div class="field">
      <label>Identyfikator Medicover</label>
      <input id="mc-user" type="text" placeholder="np. 12345678">
    </div>
    <div class="field">
      <label>Hasło Medicover</label>
      <input id="mc-pass" type="password" placeholder="Hasło do konta Medicover">
    </div>
  </div>
  <div class="row" style="margin-top:.75rem;">
    <div class="field">
      <label>Email IMAP (do odbioru kodu MFA)</label>
      <input id="smtp-user" type="email" placeholder="np. jan@interia.pl">
    </div>
    <div class="field">
      <label>Hasło email</label>
      <input id="smtp-pass" type="password" placeholder="Hasło do skrzynki email">
    </div>
    <div class="field" style="justify-content: flex-end;">
      <button class="btn-primary" onclick="login()">Zaloguj</button>
    </div>
  </div>
  <p class="note">Dane logowania są zapisywane lokalnie w accounts.json (nie trafiają do gita).</p>
</div>

<!-- 2. Nowa czujka -->
<div class="card">
  <h2>2. Nowa czujka</h2>
  <div class="row">
    <div class="field">
      <label>Region</label>
      <select id="sel-region" disabled onchange="loadSpecializations()">
        <option value="">— zaloguj się najpierw —</option>
      </select>
    </div>
    <div class="field">
      <label>Specjalizacja</label>
      <select id="sel-spec" disabled onchange="loadClinics()">
        <option value="">— wybierz region —</option>
      </select>
    </div>
    <div class="field">
      <label>Placówka</label>
      <select id="sel-clinic" disabled onchange="loadDoctors()">
        <option value="">— wybierz specjalizację —</option>
      </select>
    </div>
    <div class="field">
      <label>Lekarz (opcjonalnie)</label>
      <select id="sel-doctor" disabled>
        <option value="-1">Dowolny lekarz</option>
      </select>
    </div>
  </div>
  <div class="row" style="margin-top: 1rem;">
    <div class="field">
      <label>Typ wizyty</label>
      <div class="radio-group">
        <label><input type="radio" name="booking" value="2" checked onchange="loadSpecializations()"> Telefoniczna</label>
        <label><input type="radio" name="booking" value="1" onchange="loadSpecializations()"> Stacjonarna</label>
      </div>
    </div>
    <div class="field">
      <label>Na ile dni naprzód</label>
      <input id="days-ahead" type="number" value="30" min="1" max="90">
    </div>
    <div class="field">
      <label>Godziny od</label>
      <input id="time-from" type="time" placeholder="np. 08:00">
    </div>
    <div class="field">
      <label>Godziny do</label>
      <input id="time-to" type="time" placeholder="np. 17:00">
    </div>
    <div class="field">
      <label>Email (opcjonalnie)</label>
      <input id="watch-email" type="email" placeholder="domyślny z sekcji Email">
    </div>
    <div class="field">
      <label>Nazwa czujki</label>
      <input id="watch-name" type="text" placeholder="np. Endokrynolog Warszawa">
    </div>
    <div class="field" style="justify-content: flex-end;">
      <button class="btn-primary" onclick="addWatch()">+ Dodaj czujkę</button>
    </div>
  </div>
</div>

<!-- 3. Lista czujek -->
<div class="card">
  <h2>3. Czujki monitorowania</h2>
  <div id="watches-list"><p class="watch-empty">Brak czujek — dodaj pierwszą powyżej.</p></div>
</div>

<!-- 4. Email -->
<div class="card">
  <h2>4. Powiadomienia email</h2>
  <div class="row">
    <div class="field">
      <label>Email docelowy</label>
      <input id="email-to" type="email" placeholder="odbiorca@interia.pl">
    </div>
    <div class="field">
      <label>Serwer SMTP</label>
      <input id="smtp-host" type="text" value="poczta.interia.pl">
    </div>
    <div class="field">
      <label>Port SMTP</label>
      <input id="smtp-port" type="number" value="465">
    </div>
  </div>
  <p class="note">Hasła SMTP i Medicover ustaw jako GitHub Secrets — nie są zapisywane do config.yml.</p>
</div>

<!-- Akcje -->
<div class="card">
  <div class="actions">
    <button class="btn-success" onclick="saveConfig()">Zapisz config.yml</button>
    <button class="btn-git" onclick="gitPush()">Wypchnij do git</button>
  </div>
  <div id="status"></div>
</div>

<script>
const $ = id => document.getElementById(id);

// ---- state ----
let watches = [];
let currentRepo = 'origin';

// ---- helpers ----

function showStatus(msg, type='inf') {
  const el = $('status');
  el.className = `status-${type}`;
  el.innerHTML = msg;
  el.style.display = 'block';
}

function showSpinner(msg) {
  showStatus(`<span class="spinner"></span>${msg}`, 'inf');
}

async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function fillSelect(sel, items, defaultLabel, defaultValue='-1') {
  sel.innerHTML = `<option value="${defaultValue}">${defaultLabel}</option>`;
  for (const it of items) {
    const opt = document.createElement('option');
    opt.value = it.id;
    opt.textContent = it.name;
    sel.appendChild(opt);
  }
  sel.disabled = false;
}

function selText(sel) {
  return sel.options[sel.selectedIndex]?.text || '';
}

// ---- watches ----

function renderWatches() {
  const list = $('watches-list');
  if (!watches.length) {
    list.innerHTML = '<p class="watch-empty">Brak czujek — dodaj pierwszą powyżej.</p>';
    return;
  }
  list.innerHTML = watches.map((w, i) => `
    <div class="watch-item">
      <div>
        <div class="watch-name">${w.name || '(bez nazwy)'}</div>
        <div class="watch-detail">
          ${w._regionName} › ${w._specName} › ${w._clinicName} › ${w._doctorName}
          &nbsp;|&nbsp; ${w.booking_type == 2 ? 'Telefoniczna' : 'Stacjonarna'}
          &nbsp;|&nbsp; ${w.days_ahead} dni
          ${w.time_from || w.time_to ? `&nbsp;|&nbsp; ${w.time_from || '0:00'}–${w.time_to || '23:59'}` : ''}
          ${w.email_to ? `&nbsp;|&nbsp; ✉ ${w.email_to}` : ''}
        </div>
      </div>
      <button class="btn-danger btn-sm" onclick="removeWatch(${i})">Usuń</button>
    </div>
  `).join('');
}

function addWatch() {
  const region = $('sel-region').value;
  const spec   = $('sel-spec').value;
  if (!region || !spec) { showStatus('Wybierz przynajmniej region i specjalizację.', 'err'); return; }
  const clinic  = $('sel-clinic').value  || '-1';
  const doctor  = $('sel-doctor').value  || '-1';
  const booking  = document.querySelector('input[name="booking"]:checked').value;
  const days     = $('days-ahead').value  || '30';
  const timeFrom   = $('time-from').value   || '';
  const timeTo     = $('time-to').value     || '';
  const watchEmail   = $('watch-email').value.trim() || '';
  const autoName = `${selText($('sel-spec'))} – ${selText($('sel-region'))}`;
  const name    = $('watch-name').value.trim() || autoName;
  watches.push({
    name,
    region_id:         parseInt(region),
    specialization_id: parseInt(spec),
    clinic_id:         parseInt(clinic),
    doctor_id:         parseInt(doctor),
    booking_type:      parseInt(booking),
    days_ahead:        parseInt(days),
    time_from:         timeFrom,
    time_to:           timeTo,
    email_to:          watchEmail,
    _regionName: selText($('sel-region')),
    _specName:   selText($('sel-spec')),
    _clinicName: parseInt(clinic) > 0 ? selText($('sel-clinic')) : 'Dowolna placówka',
    _doctorName: parseInt(doctor) > 0 ? selText($('sel-doctor')) : 'Dowolny lekarz',
  });
  renderWatches();
  $('watch-name').value = '';
  showStatus(`Dodano czujkę: ${name}`, 'ok');
}

function removeWatch(i) {
  const name = watches[i].name;
  watches.splice(i, 1);
  renderWatches();
  showStatus(`Usunięto czujkę: ${name}`, 'inf');
}

// ---- login ----

async function login() {
  const user = $('mc-user').value.trim();
  const pass = $('mc-pass').value;
  const smtpUser = $('smtp-user').value.trim();
  const smtpPass = $('smtp-pass').value;
  if (!user || !pass) { showStatus('Podaj identyfikator i hasło Medicover.', 'err'); return; }
  if (!smtpUser || !smtpPass) { showStatus('Podaj dane email (do odbioru kodu MFA).', 'err'); return; }
  showSpinner('Logowanie (może potrwać do 2 min — MFA)…');
  try {
    await api('POST', '/api/login', { user, pass, smtp_user: smtpUser, smtp_pass: smtpPass, repo: currentRepo });
    // Poll login status
    while (true) {
      await new Promise(r => setTimeout(r, 2000));
      const st = await api('GET', '/api/login-status');
      if (st.state === 'working') {
        showSpinner(st.message || 'Logowanie…');
      } else if (st.state === 'done') {
        showStatus(st.message || 'Zalogowano pomyślnie. Ładuję regiony…', 'ok');
        await loadRegions();
        return;
      } else if (st.state === 'error') {
        showStatus('Błąd logowania: ' + st.message, 'err');
        return;
      }
    }
  } catch(e) {
    console.error('Login error:', e.message);
    showStatus('Błąd logowania: ' + e.message, 'err');
  }
}

// ---- cascading dropdowns ----

async function loadRegions() {
  showSpinner('Ładuję regiony…');
  try {
    const data = await api('GET', '/api/regions');
    fillSelect($('sel-region'), data.items, '— wybierz region —', '');
    showStatus('Wybierz region.', 'inf');
  } catch(e) {
    showStatus('Błąd ładowania regionów: ' + e.message, 'err');
  }
}

async function loadSpecializations() {
  const region = $('sel-region').value;
  if (!region) return;
  const booking = document.querySelector('input[name="booking"]:checked').value;
  $('sel-spec').disabled = true;
  $('sel-clinic').disabled = true;
  $('sel-doctor').disabled = true;
  showSpinner('Ładuję specjalizacje…');
  try {
    const data = await api('GET', `/api/specializations?region=${region}&booking=${booking}`);
    fillSelect($('sel-spec'), data.items, '— wybierz specjalizację —', '');
    showStatus('Wybierz specjalizację.', 'inf');
  } catch(e) {
    showStatus('Błąd ładowania specjalizacji: ' + e.message, 'err');
  }
}

async function loadClinics() {
  const region = $('sel-region').value;
  const spec   = $('sel-spec').value;
  if (!region || !spec) return;
  const booking = document.querySelector('input[name="booking"]:checked').value;
  $('sel-clinic').disabled = true;
  $('sel-doctor').disabled = true;
  showSpinner('Ładuję placówki…');
  try {
    const data = await api('GET', `/api/clinics?region=${region}&spec=${spec}&booking=${booking}`);
    fillSelect($('sel-clinic'), data.items, 'Dowolna placówka');
    showStatus('Wybierz placówkę (lub zostaw "Dowolna").', 'inf');
  } catch(e) {
    showStatus('Błąd ładowania placówek: ' + e.message, 'err');
  }
}

async function loadDoctors() {
  const region  = $('sel-region').value;
  const spec    = $('sel-spec').value;
  const clinic  = $('sel-clinic').value;
  const booking = document.querySelector('input[name="booking"]:checked').value;
  $('sel-doctor').disabled = true;
  showSpinner('Ładuję lekarzy…');
  try {
    const data = await api('GET', `/api/doctors?region=${region}&spec=${spec}&clinic=${clinic}&booking=${booking}`);
    fillSelect($('sel-doctor'), data.items, 'Dowolny lekarz');
    showStatus('Gotowe — wybierz lekarza lub zostaw "Dowolny".', 'ok');
  } catch(e) {
    showStatus('Błąd ładowania lekarzy: ' + e.message, 'err');
  }
}

// ---- save + push ----

async function saveConfig() {
  if (!watches.length) { showStatus('Dodaj przynajmniej jedną czujkę.', 'err'); return; }
  showSpinner('Zapisuję config.yml…');
  try {
    const cfg = {
      EMAIL_TO:  $('email-to').value,
      SMTP_HOST: $('smtp-host').value,
      SMTP_PORT: parseInt($('smtp-port').value) || 465,
      watches: watches.map(w => ({
        name:              w.name,
        region_id:         w.region_id,
        specialization_id: w.specialization_id,
        clinic_id:         w.clinic_id,
        doctor_id:         w.doctor_id,
        booking_type:      w.booking_type,
        days_ahead:        w.days_ahead,
        ...(w.time_from     ? {time_from:     w.time_from}     : {}),
        ...(w.time_to       ? {time_to:       w.time_to}       : {}),
        ...(w.email_to      ? {email_to:      w.email_to}      : {}),
      })),
    };
    await api('POST', '/api/save', cfg);
    showStatus('config.yml zapisany pomyślnie.', 'ok');
  } catch(e) {
    showStatus('Błąd zapisu: ' + e.message, 'err');
  }
}

async function gitPush() {
  showSpinner(`Wypycham do ${currentRepo}…`);
  try {
    const res = await api('POST', '/api/git-push', { remote: currentRepo });
    showStatus(`Git push (${currentRepo}): ` + res.output, 'ok');
  } catch(e) {
    showStatus('Błąd git: ' + e.message, 'err');
  }
}

async function loadRepos() {
  try {
    const data = await api('GET', '/api/repos');
    const sel = $('sel-repo');
    sel.innerHTML = '';
    for (const r of data.repos) {
      const opt = document.createElement('option');
      opt.value = r.name;
      opt.textContent = `${r.label} (${r.name})`;
      sel.appendChild(opt);
    }
    currentRepo = sel.value;
    $('repo-status').textContent = `Aktywne: ${currentRepo}`;
  } catch(e) { console.error(e); }
}

async function switchRepo() {
  currentRepo = $('sel-repo').value;
  $('repo-status').innerHTML = '<span class="spinner"></span>Ładuję config…';
  try {
    // Load saved account credentials for this repo
    try {
      const acc = await api('GET', `/api/account?repo=${currentRepo}`);
      if (acc.mc_user)   $('mc-user').value   = acc.mc_user;
      if (acc.mc_pass)   $('mc-pass').value   = acc.mc_pass;
      if (acc.smtp_user) $('smtp-user').value = acc.smtp_user;
      if (acc.smtp_pass) $('smtp-pass').value = acc.smtp_pass;
    } catch(e) { /* no saved account */ }
    const cfg = await api('GET', `/api/load?remote=${currentRepo}`);
    if (cfg.EMAIL_TO)  $('email-to').value  = cfg.EMAIL_TO;
    if (cfg.SMTP_HOST) $('smtp-host').value = cfg.SMTP_HOST;
    if (cfg.SMTP_PORT) $('smtp-port').value = cfg.SMTP_PORT;
    if (cfg.watches && cfg.watches.length) {
      watches = cfg.watches.map(w => ({
        ...w,
        _regionName: `Region ${w.region_id}`,
        _specName:   `Spec ${w.specialization_id}`,
        _clinicName: w.clinic_id > 0 ? `Placówka ${w.clinic_id}` : 'Dowolna placówka',
        _doctorName: w.doctor_id > 0 ? `Lekarz ${w.doctor_id}`  : 'Dowolny lekarz',
      }));
    } else {
      watches = [];
    }
    renderWatches();
    $('repo-status').textContent = `Aktywne: ${currentRepo}`;
    showStatus(`Załadowano config z ${currentRepo}.`, 'ok');
  } catch(e) {
    $('repo-status').textContent = `Aktywne: ${currentRepo} (brak config)`;
    watches = [];
    renderWatches();
  }
}

// ---- init: pre-load existing config ----

document.addEventListener('DOMContentLoaded', async () => {
  await loadRepos();
  await switchRepo();
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template_string(HTML)


import threading

_login_status = {"state": "idle", "message": ""}


@app.get("/api/login-status")
def api_login_status():
    return jsonify(**_login_status)


ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")


def _load_accounts() -> dict:
    try:
        with open(ACCOUNTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_accounts(accounts: dict):
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, ensure_ascii=False, indent=2)


@app.get("/api/account")
def api_account():
    repo = request.args.get("repo", "origin")
    accounts = _load_accounts()
    acc = accounts.get(repo, {})
    return jsonify(acc)


@app.post("/api/login")
def api_login():
    global _session
    data = request.get_json(force=True)
    user = data.get("user", "").strip()
    password = data.get("pass", "")
    smtp_user = data.get("smtp_user", "").strip()
    smtp_pass = data.get("smtp_pass", "")
    repo = data.get("repo", "origin")
    if not user or not password:
        return jsonify(error="Podaj identyfikator i hasło"), 400

    # Save credentials locally per repo
    accounts = _load_accounts()
    accounts[repo] = {
        "mc_user": user, "mc_pass": password,
        "smtp_user": smtp_user, "smtp_pass": smtp_pass,
    }
    _save_accounts(accounts)

    # Set env vars for IMAP access during MFA
    if smtp_user:
        os.environ["SMTP_USER"] = smtp_user
    if smtp_pass:
        os.environ["SMTP_PASS"] = smtp_pass

    _login_status.update(state="working", message="Logowanie…")

    def _do_login():
        global _session

        class _StatusHandler(logging.Handler):
            _msg_map = [
                ("IMAP: czekam", "Czekam na kod MFA z emaila…"),
                ("Kod MFA:", "Kod MFA odebrany — wysyłam…"),
                ("MFA detected", "MFA wymagane — pobieram kod z emaila…"),
                ("Logowanie zakończone", "Logowanie zakończone!"),
                ("SSO sesja", "SSO sesja ważna — pomijam MFA"),
            ]
            def emit(self, record):
                msg = record.getMessage()
                for trigger, status_msg in self._msg_map:
                    if trigger in msg:
                        _login_status.update(state="working", message=status_msg)
                        break

        handler = _StatusHandler()
        monitor_log = logging.getLogger("monitor")
        monitor_log.addHandler(handler)

        try:
            sess = MedicoverSession(user, password)
            if sess.load_session():
                _login_status.update(state="done", message="Zalogowano (zapisana sesja)")
                _session = sess
                return
            _login_status.update(state="working", message="Wysyłam dane logowania…")
            sess.log_in()
            sess.save_session()
            _session = sess
            _login_status.update(state="done", message="Zalogowano pomyślnie")
        except AuthError as e:
            log.error("[Login] AuthError: %s", e)
            _login_status.update(state="error", message=str(e))
        except Exception as e:
            log.error("[Login] Nieoczekiwany błąd: %s", e, exc_info=True)
            _login_status.update(state="error", message=f"Błąd serwera: {e}")
        finally:
            monitor_log.removeHandler(handler)

    threading.Thread(target=_do_login, daemon=True).start()
    return jsonify(ok=True, message="Logowanie rozpoczęte")


@app.get("/api/regions")
def api_regions():
    try:
        raw = _get_session().load_regions()
        items = _normalize_list(raw)
        return jsonify(items=items)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.get("/api/specializations")
def api_specializations():
    region = request.args.get("region", type=int)
    booking = request.args.get("booking", 2, type=int)
    try:
        data = _get_session().load_filters(region=region, bookingtype=booking)
        items = _normalize_list(data.get("specialties", data.get("specializations", data.get("services", []))))
        return jsonify(items=items)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.get("/api/clinics")
def api_clinics():
    region  = request.args.get("region", type=int)
    spec    = request.args.get("spec", type=int)
    booking = request.args.get("booking", 2, type=int)
    try:
        data = _get_session().load_filters(region=region, bookingtype=booking, specialization=spec)
        items = _normalize_list(data.get("clinics", []))
        return jsonify(items=items)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.get("/api/doctors")
def api_doctors():
    region  = request.args.get("region", type=int)
    spec    = request.args.get("spec", type=int)
    clinic  = request.args.get("clinic", -1, type=int)
    booking = request.args.get("booking", 2, type=int)
    try:
        data = _get_session().load_filters(
            region=region, bookingtype=booking, specialization=spec, clinic=clinic
        )
        items = _normalize_list(data.get("doctors", []))
        return jsonify(items=items)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.get("/api/repos")
def api_repos():
    """List git remotes as repo choices."""
    cwd = os.path.dirname(os.path.abspath(__file__))
    result = subprocess.run(["git", "remote", "-v"], cwd=cwd,
                            capture_output=True, text=True)
    repos = []
    seen = set()
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] not in seen:
            name = parts[0]
            url = parts[1]
            # Extract repo name from URL for label
            label = url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
            repos.append({"name": name, "url": url, "label": label})
            seen.add(name)
    return jsonify(repos=repos)


@app.get("/api/load")
def api_load():
    """Load config.yml from the selected remote's latest commit."""
    remote = request.args.get("remote", "origin")
    cwd = os.path.dirname(os.path.abspath(__file__))

    try:
        subprocess.run(["git", "fetch", remote, "main"], cwd=cwd,
                       capture_output=True, text=True, timeout=15)
        result = subprocess.run(
            ["git", "show", f"{remote}/main:config.yml"],
            cwd=cwd, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            data = yaml.safe_load(result.stdout) or {}
            return jsonify(data)
    except Exception:
        pass
    return jsonify({})


@app.post("/api/save")
def api_save():
    cfg = request.get_json(force=True)
    # Build output — keep watches as-is, coerce SMTP_PORT to int
    out = {
        "EMAIL_TO":  cfg.get("EMAIL_TO", ""),
        "SMTP_HOST": cfg.get("SMTP_HOST", "poczta.interia.pl"),
        "SMTP_PORT": int(cfg.get("SMTP_PORT", 465)),
        "watches":   cfg.get("watches", []),
    }

    config_path = os.path.join(os.path.dirname(__file__), "config.yml")
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(out, f, allow_unicode=True, sort_keys=False)

    return jsonify(ok=True, path=config_path)


@app.post("/api/git-push")
def api_git_push():
    data = request.get_json(force=True) if request.is_json else {}
    remote = data.get("remote", "origin")
    cwd = os.path.dirname(os.path.abspath(__file__))
    track_files = ["monitor.py", "web_config.py", "config.yml",
                   "requirements.txt", ".gitignore", ".github"]
    try:
        # Untrack __pycache__ if it was accidentally committed
        subprocess.run(
            ["git", "rm", "--cached", "-r", "--ignore-unmatch", "__pycache__"],
            cwd=cwd, capture_output=True, text=True
        )
        # Stage all tracked modified files + our specific files
        subprocess.run(["git", "add", "-u"], cwd=cwd, check=True,
                       capture_output=True, text=True)
        for f in track_files:
            if os.path.exists(os.path.join(cwd, f)):
                subprocess.run(["git", "add", f], cwd=cwd, check=True,
                               capture_output=True, text=True)

        result = subprocess.run(
            ["git", "commit", "-m", "Update monitor config"],
            cwd=cwd, capture_output=True, text=True
        )
        out = result.stdout + result.stderr
        nothing = "nothing to commit" in out or "nothing added to commit" in out
        if result.returncode != 0 and not nothing:
            raise RuntimeError(out.strip())

        # Push to selected remote
        push = subprocess.run(
            ["git", "push", remote, "main"],
            cwd=cwd, check=True, capture_output=True, text=True
        )
        push_out = push.stdout or push.stderr or f"Wypchnięto do {remote} pomyślnie."
        return jsonify(ok=True, output=push_out)
    except subprocess.CalledProcessError as e:
        return jsonify(error=(e.stderr or e.stdout or str(e))), 500
    except Exception as e:
        return jsonify(error=str(e)), 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_list(items: list) -> list[dict]:
    """Normalize API filter items to [{id, name}] format."""
    result = []
    for it in items:
        if isinstance(it, dict):
            item_id   = it.get("id", it.get("value", "?"))
            item_name = it.get("text", it.get("name", it.get("value", str(it))))
        else:
            item_id = item_name = str(it)
        result.append({"id": item_id, "name": item_name})
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import webbrowser
    print("Medicover Monitor — Konfigurator")
    print("Otwórz w przeglądarce: http://localhost:5000")
    print("Zatrzymaj: Ctrl+C\n")
    if "--no-browser" not in sys.argv:
        webbrowser.open("http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
