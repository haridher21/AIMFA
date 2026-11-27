// AIMFA dashboard: live refresh + buttons. No framework, no third-party code.
//
// - Every <section class="live" data-src=... data-every=...> re-fetches its HTML from the
//   server on a timer and swaps it in. Typed text in inputs (the TOTP box) survives the swap.
// - Buttons with data-action POST JSON with our CSRF token, show the answer, then refresh.
// - Buttons with data-fetch GET some HTML into the element named by data-target.
// Server HTML is already escaped by Jinja; messages from JSON are set as text, never HTML.
"use strict";

const CSRF = document.querySelector('meta[name="csrf-token"]')?.content ?? "";

function applyBars(root) {
  // Bar widths and threshold positions come from data-pct (CSP blocks inline style="").
  root.querySelectorAll("[data-pct]").forEach((el) => {
    const pct = Math.max(0, Math.min(100, Number(el.dataset.pct) || 0));
    el.style.setProperty(el.dataset.pctProp || "width", `${pct}%`);
  });
}

function saveInputs(root) {
  const saved = new Map();
  root.querySelectorAll("input[id]").forEach((el) => {
    saved.set(el.id, {
      value: el.value,
      focused: document.activeElement === el,
      start: el.selectionStart,
      end: el.selectionEnd,
    });
  });
  return saved;
}

function restoreInputs(root, saved) {
  saved.forEach((s, id) => {
    const el = document.getElementById(id);
    if (!el || !root.contains(el)) return;
    el.value = s.value;
    if (s.focused) {
      el.focus();
      try { el.setSelectionRange(s.start, s.end); } catch { /* not a text input */ }
    }
  });
}

async function refresh(region) {
  if (region.dataset.busy) return;
  region.dataset.busy = "1";
  try {
    const resp = await fetch(region.dataset.src, { cache: "no-store" });
    if (!resp.ok) return;
    const html = await resp.text();
    const saved = saveInputs(region);
    region.innerHTML = html;
    restoreInputs(region, saved);
    applyBars(region);
  } catch {
    // Dashboard server unreachable: keep showing the last good view.
  } finally {
    delete region.dataset.busy;
  }
}

function refreshAll() {
  document.querySelectorAll(".live[data-src]").forEach(refresh);
}

let toastTimer;
function toast(kind, message) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.className = `toast toast-${kind}`;
  el.textContent = message; // text, never HTML
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, kind === "success" ? 4000 : 8000);
}

async function runAction(btn) {
  const body = btn.dataset.body ? JSON.parse(btn.dataset.body) : {};
  const input = btn.dataset.input ? document.getElementById(btn.dataset.input) : null;
  if (input) body.code = input.value.trim();
  if (btn.dataset.modeFrom) {
    body.mode = document.querySelector(`input[name="${btn.dataset.modeFrom}"]:checked`)?.value;
  }
  const group = btn.closest("[data-group]") || btn.parentElement;
  const buttons = group.querySelectorAll("button");
  buttons.forEach((b) => { b.disabled = true; });
  btn.classList.add("busy");
  try {
    const resp = await fetch(btn.dataset.action, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(body),
    });
    let result;
    try {
      result = await resp.json();
    } catch {
      result = null;
    }
    if (result && typeof result.ok === "boolean") {
      toast(result.kind, result.message);
      if (result.ok && input) input.value = "";
    } else {
      const code = result?.reason_code ? ` ${result.reason_code}` : "";
      toast("error", `Request refused (HTTP ${resp.status}${code}).`);
    }
  } catch {
    toast("warning", "Dashboard server is not reachable.");
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
    btn.classList.remove("busy");
    refreshAll();
  }
}

async function runFetch(btn) {
  const target = document.getElementById(btn.dataset.target);
  if (!target) return;
  btn.disabled = true;
  btn.classList.add("busy");
  try {
    const resp = await fetch(btn.dataset.fetch, { cache: "no-store" });
    target.innerHTML = await resp.text();
  } catch {
    toast("warning", "Dashboard server is not reachable.");
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
  }
}

document.addEventListener("click", (event) => {
  const action = event.target.closest("button[data-action]");
  if (action) { runAction(action); return; }
  const fetcher = event.target.closest("button[data-fetch]");
  if (fetcher) runFetch(fetcher);
});

// Enter in a TOTP box presses that card's Approve button.
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" || !event.target.matches?.("input.code-input")) return;
  const approve = event.target.closest(".decide")?.querySelector("button.btn-primary");
  if (approve) approve.click();
});

document.addEventListener("DOMContentLoaded", () => {
  applyBars(document);
  document.querySelectorAll(".live[data-every]").forEach((region) => {
    const every = Math.max(1000, Number(region.dataset.every) || 2500);
    setInterval(() => { if (!document.hidden) refresh(region); }, every);
  });
});
