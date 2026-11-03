"use strict";
/* MediScript - UI. All text is inserted via textContent (no innerHTML). */

const state = { me: null, csrf: null, page: "patients", patientId: null, idleLeft: 0, idleMax: 600 };
const $app = document.getElementById("app");
let idleTimer = null;

const ROLE_LABEL = { pflege: "Pflegekraft", stationsleitung: "Stationsleitung", pdl: "Pflegedienstleitung" };
const DETAIL_LABEL = { assignment: "über Stationszuordnung", break_glass: "über Notfallzugriff",
  patient_view: "Aktenansicht", assist: "Assistent", report_sign: "Berichtsfreigabe" };
const ACTION_LABEL = {
  login_ok: "Anmeldung", login_failed: "Anmeldung fehlgeschlagen", totp_failed: "2. Faktor falsch",
  login_locked: "Konto gesperrt (Versuche)", logout: "Abmeldung", patient_view: "Patientenkarte geöffnet",
  patient_list: "Stationsliste", access_denied: "Zugriff verweigert", break_glass: "NOTFALLZUGRIFF",
  break_glass_reviewed: "Notfallzugriff geprüft", assist_used: "Assistent genutzt",
  report_signed: "Bericht unterschrieben", access_requested: "Zugriff beantragt",
  access_granted: "Zugriff genehmigt", access_rejected: "Zugriff abgelehnt",
  access_revoked: "Zugriff entzogen", user_deactivated: "Konto deaktiviert",
  anomaly_bulk_access: "Auffällig: viele Akten", csrf_blocked: "Anfrage blockiert",
  system_seeded: "System eingerichtet",
};

// ---------- tiny DOM helper ----------
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const fmt = (iso) => iso ? new Date(iso).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "–";
const fmtDay = (iso) => iso ? new Date(iso).toLocaleDateString("de-DE") : "–";

function toast(msg, error) {
  let box = document.getElementById("toasts");
  if (!box) { box = h("div", { id: "toasts" }); document.body.append(box); }
  const t = h("div", { class: "toast" + (error ? " error" : ""), role: "status" }, msg);
  box.append(t);
  setTimeout(() => t.remove(), 4500);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
  const res = await fetch(path, {
    method: opts.method || "GET", headers, credentials: "same-origin",
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (res.status === 401 && state.me) { endSession("Sitzung beendet. Bitte neu anmelden."); throw new Error("401"); }
  if (!res.ok) {
    const detail = data && data.detail;
    const err = new Error(typeof detail === "string" ? detail : (detail && detail.message) || "Fehler");
    err.status = res.status; err.detail = detail;
    throw err;
  }
  resetIdle();
  return data;
}

// ---------- session / idle lock ----------
function resetIdle() { state.idleLeft = state.idleMax; }
function startIdleTimer() {
  clearInterval(idleTimer);
  resetIdle();
  idleTimer = setInterval(() => {
    state.idleLeft -= 1;
    paintIdle();
    if (state.idleLeft <= 0) logout("Aus Sicherheitsgründen automatisch abgemeldet.");
  }, 1000);
}
function paintIdle() {
  const el = document.getElementById("idle");
  if (!el) return;
  const m = Math.floor(state.idleLeft / 60), s = String(Math.max(0, state.idleLeft) % 60).padStart(2, "0");
  el.textContent = `Auto-Sperre in ${m}:${s}`;
  el.classList.toggle("warn", state.idleLeft < 60);
}
["click", "keydown", "pointerdown"].forEach((e) => document.addEventListener(e, () => { if (state.me) resetIdle(); }, { passive: true }));

function endSession(message) {
  clearInterval(idleTimer);
  state.me = null; state.csrf = null; state.page = "patients"; state.patientId = null;
  renderLogin(message);
}
async function logout(message) {
  try { await api("/api/logout", { method: "POST" }); } catch (_) { /* session may already be gone */ }
  endSession(message);
}
function adopt(payload) {
  state.me = payload;
  state.csrf = payload.csrf;
  state.idleMax = payload.idle_seconds;
  startIdleTimer();
  go("patients");
}

// ---------- login ----------
const LOGO = () => {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 32 32"); svg.setAttribute("aria-hidden", "true");
  const moon = document.createElementNS(ns, "path");
  moon.setAttribute("d", "M22 4a12 12 0 1 0 6 20A10 10 0 0 1 22 4z");
  moon.setAttribute("fill", "#9aae88");
  const cross = document.createElementNS(ns, "path");
  cross.setAttribute("d", "M12 11h3v4h4v3h-4v4h-3v-4H8v-3h4z");
  cross.setAttribute("fill", "#b4534a");
  svg.append(moon, cross);
  return svg;
};

function renderLogin(message) {
  $app.replaceChildren();
  const err = h("div", { class: "notice error hidden", role: "alert" });
  const info = message ? h("div", { class: "notice warn" }, message) : null;
  const user = h("input", { id: "u", autocomplete: "username", required: true, maxlength: 64 });
  const pass = h("input", { id: "p", type: "password", autocomplete: "current-password", required: true, maxlength: 200 });
  const code = h("input", { id: "c", inputmode: "numeric", pattern: "[0-9]{6}", maxlength: 6, autocomplete: "one-time-code" });
  const step1 = h("form", {}, h("label", { for: "u" }, "Benutzername"), user,
    h("label", { for: "p" }, "Passwort"), pass,
    h("p", {}, h("button", { class: "btn btn-primary", type: "submit" }, "Weiter")));
  const step2 = h("form", { class: "hidden" }, h("label", { for: "c" }, "6-stelliger Code aus der Authenticator-App oder vom Dienstausweis"), code,
    h("p", {}, h("button", { class: "btn btn-primary", type: "submit" }, "Anmelden")));
  const showErr = (m) => { err.textContent = m; err.classList.remove("hidden"); };
  let pre = null;

  async function doStep1(u, p) {
    const r = await api("/api/login", { method: "POST", body: { username: u, password: p } });
    pre = r.pre_token;
    step1.classList.add("hidden"); step2.classList.remove("hidden"); code.focus();
  }
  async function doStep2(c) {
    adopt(await api("/api/login/totp", { method: "POST", body: { pre_token: pre, code: c } }));
  }
  step1.addEventListener("submit", async (e) => {
    e.preventDefault(); err.classList.add("hidden");
    try { await doStep1(user.value.trim(), pass.value); } catch (x) { showErr(x.message); }
  });
  step2.addEventListener("submit", async (e) => {
    e.preventDefault(); err.classList.add("hidden");
    try { await doStep2(code.value.trim()); } catch (x) { showErr(x.message); if (x.status === 401) { step2.classList.add("hidden"); step1.classList.remove("hidden"); pass.value = ""; } }
  });

  const demo = h("div", { class: "demo-box hidden" });
  const card = h("div", { class: "panel login-card" },
    h("div", { class: "brand" }, LOGO(), "MediScript"),
    h("p", { class: "dim small" }, "Pflege-Assistent für Krankenhäuser. Nur für autorisiertes Personal. Alle Zugriffe werden protokolliert."),
    info, err, step1, step2, demo,
    h("p", { class: "dim small" }, "Prototyp mit ausschließlich fiktiven Daten."));
  $app.append(h("div", { class: "login-wrap" }, card));
  user.focus();
  loadDemo(demo, doStep1, doStep2);
}

async function loadDemo(box, doStep1, doStep2) {
  try {
    const res = await fetch("/api/demo/credentials", { credentials: "same-origin" });
    if (!res.ok) return;
    const { accounts } = await res.json();
    if (!accounts.length) return;
    box.classList.remove("hidden");
    box.append(h("h3", {}, "DEMO-MODUS (nur lokal, in Produktion abgeschaltet)"));
    for (const a of accounts) {
      box.append(h("div", { class: "demo-row" },
        h("span", {}, a.display_name, " ", h("span", { class: "badge" }, ROLE_LABEL[a.role])),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: async () => {
          try {
            const fresh = await (await fetch("/api/demo/credentials")).json();
            const acc = fresh.accounts.find((x) => x.username === a.username);
            await doStep1(acc.username, acc.password);
            await doStep2(acc.code);
          } catch (x) { toast(x.message, true); }
        } }, "Anmelden")));
    }
  } catch (_) { /* not in demo mode */ }
}

// ---------- shell ----------
function go(page, patientId) {
  state.page = page; state.patientId = patientId || null;
  renderShell();
}
function isAdmin() { return ["stationsleitung", "pdl"].includes(state.me.user.role); }

function renderShell() {
  $app.replaceChildren();
  const nav = [["patients", "Patienten"]];
  if (isAdmin()) nav.push(["access", "Zugriffe verwalten"], ["audit", "Protokoll"]);
  const main = h("main", { id: "main" });
  const u = state.me.user;
  $app.append(
    h("header", { class: "topbar" }, h("div", { class: "topbar-inner" },
      h("div", { class: "brand" }, LOGO(), "MediScript"),
      h("nav", { class: "nav", "aria-label": "Hauptnavigation" }, nav.map(([id, label]) =>
        h("button", { type: "button", "aria-current": (state.page === id || (id === "patients" && state.page === "patient")) ? "page" : false, onclick: () => go(id) }, label))),
      h("div", { class: "who" }, h("strong", {}, u.display_name), h("span", { class: "dim" }, ROLE_LABEL[u.role], " · "),
        h("span", { id: "idle", class: "timer dim" }, ""), " ",
        h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => logout("Abgemeldet.") }, "Abmelden")))),
    main);
  paintIdle();
  ({ patients: viewPatients, patient: viewPatient, access: viewAccess, audit: viewAudit })[state.page](main);
}

async function guard(fn) {
  try { return await fn(); } catch (e) { if (e.message !== "401") toast(e.message, true); return null; }
}

// ---------- patients ----------
async function viewPatients(main) {
  const lookup = h("input", { placeholder: "z. B. P-0004", maxlength: 8, "aria-label": "Patienten-Code" });
  main.append(h("h1", {}, "Patienten"),
    h("p", { class: "dim" }, "Sie sehen nur Patienten der Stationen, für die Sie aktuell eingeteilt sind."),
    h("div", { id: "assign" }));
  const data = await guard(() => api("/api/patients"));
  if (!data) return;
  const assign = main.querySelector("#assign");
  if (state.me.assignments.length) {
    assign.append(h("p", { class: "small" }, "Ihr Zugriff: ", state.me.assignments.map((a) =>
      h("span", { class: "badge swamp" }, `${a.ward_name} bis ${fmtDay(a.valid_until)}`)).flatMap((b) => [b, " "])));
  } else {
    assign.append(h("div", { class: "notice warn" }, "Ihnen ist aktuell keine Station zugewiesen. Bitte wenden Sie sich an Ihre Stationsleitung."));
  }
  const byWard = {};
  data.patients.forEach((p) => { (byWard[p.ward_name] ||= []).push(p); });
  for (const [ward, list] of Object.entries(byWard)) {
    main.append(h("h2", {}, ward), h("div", { class: "grid" }, list.map(patientCard)));
  }
  main.append(h("div", { class: "panel navy" },
    h("h3", {}, "Patient außerhalb Ihrer Station"),
    h("p", { class: "dim small" }, "Im Notfall können Sie mit Begründung zugreifen. Jeder Notfallzugriff wird protokolliert und von der Pflegedienstleitung geprüft."),
    h("div", { class: "row" }, h("div", {}, h("label", {}, "Patienten-Code"), lookup),
      h("div", { class: "shrink" }, h("button", { class: "btn btn-ghost", type: "button", onclick: () => {
        const m = /^P-?(\d{1,4})$/i.exec(lookup.value.trim());
        if (!m) return toast("Bitte Code im Format P-0004 eingeben.", true);
        go("patient", Number(m[1]));
      } }, "Öffnen")))));
}

function patientCard(p) {
  const risk = p.mobility === "bettlaegerig";
  return h("button", { class: "card" + (p.mode === "break_glass" ? " bg" : ""), "data-tab": p.mode === "break_glass" ? "Notfallzugriff" : `Zimmer ${p.room}`, type: "button", onclick: () => go("patient", p.id) },
    h("span", { class: "stripe" + (risk ? " risk" : "") }),
    h("h3", {}, p.name), h("div", { class: "meta" }, `${p.age} Jahre · ${p.code}`), h("div", { class: "meta" }, p.diagnosis));
}

// ---------- break-glass dialog ----------
function breakGlassDialog(pid) {
  const reason = h("textarea", { maxlength: 300, "aria-label": "Begründung", placeholder: "Begründung (mind. 15 Zeichen), z. B. Notfall in Zimmer 2xx, Stationsvertretung ..." });
  const overlay = h("div", { class: "overlay", role: "dialog", "aria-modal": "true", "aria-label": "Notfallzugriff" },
    h("div", { class: "dialog" },
      h("h2", {}, "Kein Zugriff auf diese Akte"),
      h("p", {}, "Sie sind dieser Patientin oder diesem Patienten nicht zugeordnet."),
      h("div", { class: "notice warn" }, "Notfallzugriff gilt 30 Minuten, wird mit Ihrem Namen und der Begründung protokolliert und von der Pflegedienstleitung geprüft."),
      reason,
      h("p", { class: "actions" },
        h("button", { class: "btn btn-danger", type: "button", onclick: async () => {
          const ok = await guard(() => api(`/api/patients/${pid}/break-glass`, { method: "POST", body: { reason: reason.value } }));
          if (ok) { overlay.remove(); renderShell(); }
        } }, "Notfallzugriff aktivieren"),
        h("button", { class: "btn btn-ghost", type: "button", onclick: () => { overlay.remove(); go("patients"); } }, "Abbrechen"))));
  document.body.append(overlay);
  reason.focus();
}

// ---------- patient detail + assistant ----------
async function viewPatient(main) {
  let p;
  try { p = await api(`/api/patients/${state.patientId}`); }
  catch (e) {
    if (e.status === 403) { main.append(h("p", { class: "dim" }, "Zugriff wird geprüft …")); return breakGlassDialog(state.patientId); }
    if (e.message !== "401") toast(e.message, true);
    return;
  }
  const facts = Object.entries({ mobility: { bettlaegerig: "bettlägerig", eingeschraenkt: "Mobilität eingeschränkt", mobil: "mobil" }[p.facts.mobility] })
    .map(([, v]) => v).filter(Boolean);
  if (p.facts.fall_history) facts.push("Sturz in der Vorgeschichte");
  if (p.facts.confusion) facts.push("zeitweise verwirrt");
  if (p.facts.pain) facts.push("Schmerzen");
  if (p.facts.diabetes) facts.push("Diabetes");
  if (p.facts.postop) facts.push("postoperativ");

  main.append(
    h("p", {}, h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => go("patients") }, "← Zurück")),
    h("div", { class: "panel" },
      h("div", { class: "row" },
        h("div", {}, h("h1", {}, p.name), h("div", { class: "dim" }, `${p.age} Jahre · Zimmer ${p.room} · ${p.ward_name} · ${p.code}`)),
        h("div", { class: "shrink" }, p.mode === "break_glass" ? h("span", { class: "badge coral" }, "Notfallzugriff aktiv") : h("span", { class: "badge swamp" }, "Zugeordnet"))),
      h("p", {}, h("strong", {}, p.diagnosis)),
      h("p", { class: "dim" }, p.notes),
      h("p", {}, facts.map((f) => [h("span", { class: "badge" }, f), " "]))));

  const summary = h("textarea", { "aria-label": "Schichtzusammenfassung", placeholder: "Schichtzusammenfassung frei eintippen oder diktieren (Diktierfunktion des Geräts), z. B.: Herr Brandt wurde gewaschen. RR 128/76, Puls 82 ..." });
  const out = h("div", {});
  const left = h("div", { class: "panel navy" }, h("h2", {}, "Bericht vorbereiten"),
    h("p", { class: "dim small" }, "Der Assistent sortiert Ihre Angaben und fragt nach, was laut Pflegestandard noch fehlt. Er entscheidet nichts. Sie prüfen und unterschreiben."),
    summary, h("p", {}, h("button", { class: "btn btn-primary", type: "button", onclick: async () => {
      const r = await guard(() => api(`/api/patients/${p.id}/assist`, { method: "POST", body: { summary: summary.value } }));
      if (r) renderDraft(out, p.id, r);
    } }, "Bericht entwerfen")), out);

  const right = h("div", { class: "panel" }, h("h2", {}, "Berichtsverlauf"));
  if (!p.reports.length) right.append(h("p", { class: "dim" }, "Noch keine Berichte."));
  p.reports.forEach((r) => {
    const dis = Object.entries(r.dismissals);
    right.append(h("div", { class: "report" }, h("div", { class: "small dim" }, `${r.author} · ${fmt(r.created_at)}`), r.text,
      dis.length ? h("div", { class: "small dim" }, `Begründet nicht zutreffend: ${dis.map(([, v]) => v).join(" · ")}`) : null));
  });
  main.append(h("div", { class: "split" }, left, right));
}

function renderDraft(out, pid, result) {
  out.replaceChildren();
  const draft = h("textarea", { "aria-label": "Berichtsentwurf", style: false }, "");
  draft.value = result.draft_text;
  const qBox = h("div", {});
  const inputs = {};
  function drawQuestions(questions) {
    qBox.replaceChildren();
    for (const k of Object.keys(inputs)) delete inputs[k];
    if (!questions.length) { qBox.append(h("div", { class: "notice" }, "Keine offenen Rückfragen laut hinterlegten Standards.")); return; }
    qBox.append(h("h3", {}, `${questions.length} Rückfrage${questions.length > 1 ? "n" : ""}`),
      h("p", { class: "dim small" }, "Ergänzen Sie den Text oben und prüfen Sie erneut, oder tragen Sie eine kurze Begründung ein, wenn die Frage nicht zutrifft."));
    questions.forEach((q) => {
      const inp = h("input", { placeholder: "Nicht zutreffend, weil …", maxlength: 200, "aria-label": `Begründung zu: ${q.question}` });
      inputs[q.id] = inp;
      qBox.append(h("div", { class: "question" }, h("div", {}, q.question),
        h("div", { class: "src" }, `${q.source} · weil: ${q.because}`), inp));
    });
  }
  drawQuestions(result.questions);
  out.append(h("h3", {}, "Entwurf (bearbeitbar)"), draft, qBox,
    h("p", { class: "dim small" }, result.disclaimer),
    h("div", { class: "actions" },
      h("button", { class: "btn btn-ghost", type: "button", onclick: async () => {
        const r = await guard(() => api(`/api/patients/${pid}/assist`, { method: "POST", body: { summary: draft.value, recheck: true } }));
        if (r) drawQuestions(r.questions);
      } }, "Erneut prüfen"),
      h("button", { class: "btn btn-primary", type: "button", onclick: async () => {
        const dismissals = {};
        Object.entries(inputs).forEach(([id, el]) => { if (el.value.trim()) dismissals[id] = el.value.trim(); });
        const ok = await guard(() => api(`/api/patients/${pid}/reports`, { method: "POST", body: { text: draft.value, dismissals } }).catch((e) => {
          if (e.status === 422 && e.detail && e.detail.missing) toast("Bitte alle Rückfragen ergänzen oder begründen.", true);
          else throw e;
          return null;
        }));
        if (ok) { toast("Bericht unterschrieben und gespeichert."); renderShell(); }
      } }, "Prüfen und unterschreiben")));
}

// ---------- access management ----------
async function viewAccess(main) {
  const d = await guard(() => api("/api/admin/overview"));
  if (!d) return;
  const me = state.me.user;
  main.append(h("h1", {}, "Zugriffe verwalten"),
    h("p", { class: "dim" }, "Zugriff nur nach Bedarf: befristet, begründet und nach dem Vier-Augen-Prinzip genehmigt. Diese Ansicht zeigt keine Patientendaten."));

  const person = h("select", { "aria-label": "Person" }, d.users.filter((u) => u.active && u.id !== me.id).map((u) => h("option", { value: u.id }, u.display_name)));
  const ward = h("select", { "aria-label": "Station" }, d.manageable_wards.map((w) => h("option", { value: w.id }, w.name)));
  const until = h("input", { type: "date", "aria-label": "Gültig bis" });
  const t = new Date(); t.setDate(t.getDate() + 5); until.value = t.toISOString().slice(0, 10);
  const mx = new Date(); mx.setDate(mx.getDate() + d.max_days); until.max = mx.toISOString().slice(0, 10);
  until.min = new Date().toISOString().slice(0, 10);
  const reason = h("input", { maxlength: 300, placeholder: "Grund, z. B. Springerdienst Nachtschicht", "aria-label": "Begründung" });
  main.append(h("div", { class: "panel" }, h("h2", {}, "Zugriff beantragen"),
    h("div", { class: "row" }, h("div", {}, h("label", {}, "Person"), person), h("div", {}, h("label", {}, "Station"), ward),
      h("div", {}, h("label", {}, "Gültig bis"), until)),
    h("label", {}, "Begründung"), reason,
    h("p", {}, h("button", { class: "btn btn-primary", type: "button", disabled: !d.manageable_wards.length, onclick: async () => {
      const ok = await guard(() => api("/api/admin/requests", { method: "POST", body: { target_user_id: Number(person.value), ward_id: Number(ward.value), valid_until: until.value, reason: reason.value } }));
      if (ok) { toast("Antrag gestellt. Eine zweite Person muss genehmigen."); renderShell(); }
    } }, "Antrag stellen"))));

  const pending = d.requests.filter((r) => r.status === "pending");
  main.append(h("div", { class: "panel" }, h("h2", {}, "Offene Anträge (Vier-Augen-Prinzip)"),
    pending.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Person", "Station", "Bis", "Grund", "Beantragt von", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, pending.map((r) => h("tr", {}, h("td", {}, r.target_name), h("td", {}, r.ward_name), h("td", {}, fmtDay(r.valid_until)), h("td", {}, r.reason), h("td", {}, r.requester_name),
        h("td", {}, r.can_decide ? h("div", { class: "actions" },
          h("button", { class: "btn btn-primary btn-sm", type: "button", onclick: async () => { if (await guard(() => api(`/api/admin/requests/${r.id}/decide`, { method: "POST", body: { approve: true } }))) { toast("Genehmigt."); renderShell(); } } }, "Genehmigen"),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: async () => { if (await guard(() => api(`/api/admin/requests/${r.id}/decide`, { method: "POST", body: { approve: false } }))) renderShell(); } }, "Ablehnen"))
          : h("span", { class: "dim small" }, r.requester_name === me.display_name ? "Wartet auf zweite Person" : "Keine Berechtigung")))))))
      : h("p", { class: "dim" }, "Keine offenen Anträge.")));

  main.append(h("div", { class: "panel" }, h("h2", {}, "Personal und aktueller Zugriff"),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Person", "Rolle", "Letzte Anmeldung", "Zugriff", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, d.users.map((u) => h("tr", {},
        h("td", {}, u.display_name, " ", !u.active ? h("span", { class: "badge coral" }, "deaktiviert") : null),
        h("td", {}, ROLE_LABEL[u.role]),
        h("td", {}, fmt(u.last_login), " ", u.stale ? h("span", { class: "badge coral" }, "lange inaktiv") : null),
        h("td", {}, u.assignments.length ? u.assignments.map((a) => h("div", { class: "actions" },
          h("span", { class: "badge " + (a.expires_soon ? "coral" : "swamp") }, `${a.ward_name} bis ${fmtDay(a.valid_until)}`),
          d.manageable_wards.some((w) => w.id === a.ward_id) ? h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: async () => { if (await guard(() => api(`/api/admin/assignments/${a.id}/revoke`, { method: "POST" }))) { toast("Zugriff entzogen."); renderShell(); } } }, "Entziehen") : null))
          : h("span", { class: "dim small" }, "kein Zugriff")),
        h("td", {}, me.role === "pdl" && u.active && u.id !== me.id ? h("button", { class: "btn btn-danger btn-sm", type: "button", onclick: async () => { if (confirm(`${u.display_name} wirklich deaktivieren? Alle Zugriffe und Sitzungen enden sofort.`) && await guard(() => api(`/api/admin/users/${u.id}/deactivate`, { method: "POST" }))) { toast("Konto deaktiviert."); renderShell(); } } }, "Austritt") : null))))))));
}

// ---------- audit ----------
async function viewAudit(main) {
  const [feed, verify] = await Promise.all([guard(() => api("/api/audit?limit=150")), guard(() => api("/api/audit/verify"))]);
  if (!feed) return;
  main.append(h("h1", {}, "Protokoll"),
    h("p", { class: "dim" }, "Jeder Zugriff wird festgehalten. Einträge sind verkettet: nachträgliche Änderungen fallen auf. Es werden nie Patientennamen oder Berichtstexte protokolliert."),
    h("div", { class: "panel navy" }, h("span", { class: "chain" }, h("span", { class: "dot" + (verify && verify.ok ? "" : " bad") }),
      verify ? (verify.ok ? `Protokollkette intakt (${verify.count} Einträge)` : `MANIPULATION erkannt ab Eintrag ${verify.first_bad_id}`) : "Prüfung nicht möglich")));

  if (state.me.user.role === "pdl") {
    const bg = await guard(() => api("/api/break-glass"));
    if (bg) main.append(h("div", { class: "panel" }, h("h2", {}, "Notfallzugriffe zur Prüfung"),
      bg.entries.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Zeit", "Person", "Patient", "Begründung", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, bg.entries.map((e) => h("tr", { class: e.reviewed ? "" : "flag" }, h("td", {}, fmt(e.created_at)), h("td", {}, e.user), h("td", {}, e.patient_code), h("td", {}, e.reason),
          h("td", {}, e.reviewed ? h("span", { class: "badge swamp" }, "geprüft") : h("button", { class: "btn btn-primary btn-sm", type: "button", onclick: async () => {
            const note = prompt("Prüfvermerk (z. B. plausibel, Notfall bestätigt):", "plausibel");
            if (note !== null && await guard(() => api(`/api/break-glass/${e.id}/review`, { method: "POST", body: { note } }))) renderShell();
          } }, "Prüfen")))))))
        : h("p", { class: "dim" }, "Keine Notfallzugriffe.")));
  }
  main.append(h("div", { class: "panel" }, h("h2", {}, "Letzte Ereignisse"),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Zeit", "Person", "Ereignis", "Patient", "Details", "IP"].map((x) => h("th", {}, x)))),
      h("tbody", {}, feed.entries.map((e) => h("tr", { class: e.flagged ? "flag" : "" }, h("td", {}, fmt(e.ts)), h("td", {}, e.username || "–"), h("td", {}, ACTION_LABEL[e.action] || e.action),
        h("td", {}, e.patient_code || "–"), h("td", {}, DETAIL_LABEL[e.detail] || e.detail, e.reason ? ` · „${e.reason}“` : ""), h("td", { class: "dim small" }, e.ip))))))));
}

// ---------- boot ----------
(async function boot() {
  try {
    const me = await fetch("/api/me", { credentials: "same-origin" });
    if (me.ok) return adopt(await me.json());
  } catch (_) { /* fall through to login */ }
  renderLogin();
})();
