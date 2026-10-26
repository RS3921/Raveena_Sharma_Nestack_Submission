"use strict";

let sessionToken = null;
let activityCount = 0;

const $ = (selector) => document.querySelector(selector);
const activityList = $("#activity-list");
const responseBody = $("#response-body");
const responseStatus = $("#response-status");
const tabs = [...document.querySelectorAll('[role="tab"]')];
const flowSteps = [...document.querySelectorAll(".flow-step")];
const backendState = $("#backend-state");
$("#backend-host").textContent = window.location.host;

if (window.matchMedia("(prefers-reduced-motion: no-preference)").matches) {
  let glowFrame = 0;
  window.addEventListener("pointermove", (event) => {
    if (glowFrame) return;
    glowFrame = window.requestAnimationFrame(() => {
      document.documentElement.style.setProperty("--glow-x", `${event.clientX}px`);
      document.documentElement.style.setProperty("--glow-y", `${event.clientY}px`);
      glowFrame = 0;
    });
  }, { passive: true });
  document.documentElement.addEventListener("pointerleave", () => {
    document.documentElement.style.removeProperty("--glow-x");
    document.documentElement.style.removeProperty("--glow-y");
  });
}

function showFlowStage(stage, { error = false, complete = false } = {}) {
  flowSteps.forEach((step, index) => {
    const done = complete ? index <= stage : index < stage;
    const active = !complete && index === stage;
    step.classList.toggle("is-done", done);
    step.classList.toggle("is-active", active);
    step.classList.toggle("is-error", active && error);
    if (active) step.setAttribute("aria-current", "step");
    else step.removeAttribute("aria-current");
  });
}

function activateTab(tab, moveFocus = false) {
  tabs.forEach((item) => {
    const selected = item === tab;
    item.classList.toggle("active", selected);
    item.setAttribute("aria-selected", String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute("aria-controls")).hidden = !selected;
  });
  if (moveFocus) tab.focus();
}

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => activateTab(tab));
  tab.addEventListener("keydown", (event) => {
    let nextIndex = index;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = tabs.length - 1;
    else return;
    event.preventDefault();
    activateTab(tabs[nextIndex], true);
  });
});

function appendActivity(method, path, description, status = null) {
  const empty = activityList.querySelector(".empty-state");
  if (empty) empty.remove();
  activityCount += 1;
  const row = document.createElement("div");
  row.className = "activity-item";
  const code = status === null ? "…" : String(status);
  const statusClass = status === null ? "pending" : status < 400 ? "success" : "failure";
  const index = document.createElement("span");
  index.className = "activity-index";
  index.textContent = String(activityCount).padStart(2, "0");
  const main = document.createElement("div");
  main.className = "activity-main";
  const route = document.createElement("div");
  route.className = "activity-route";
  const methodLabel = document.createElement("span");
  methodLabel.className = `method method-${method.toLowerCase()}`;
  methodLabel.textContent = method;
  const routeLabel = document.createElement("code");
  routeLabel.textContent = path;
  route.append(methodLabel, routeLabel);
  const detail = document.createElement("p");
  detail.textContent = description;
  main.append(route, detail);
  const statusLabel = document.createElement("span");
  statusLabel.className = `activity-code ${statusClass}`;
  statusLabel.textContent = code;
  row.append(index, main, statusLabel);
  activityList.prepend(row);
  return row;
}

async function sendRequest(method, path, description, payload = undefined, authenticated = false) {
  const row = appendActivity(method, path, description);
  showFlowStage(0);
  backendState.textContent = "SENDING";
  backendState.closest(".live-badge").classList.add("is-busy");
  const headers = {};
  if (payload !== undefined) headers["Content-Type"] = "application/json";
  if (authenticated && sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
  try {
    const response = await fetch(path, {
      method,
      headers,
      body: payload === undefined ? undefined : JSON.stringify(payload),
      cache: "no-store",
    });
    const raw = await response.text();
    let data = null;
    if (raw) {
      try { data = JSON.parse(raw); } catch { data = { response: raw }; }
    }
    const status = response.status;
    row.querySelector(".activity-code").textContent = String(status);
    row.querySelector(".activity-code").className = `activity-code ${status < 400 ? "success" : "failure"}`;
    responseStatus.textContent = `${status} ${response.statusText}`;
    responseStatus.className = `status-pill ${status < 400 ? "status-ok" : "status-error"}`;
    responseBody.textContent = data === null ? "No response body (204 No Content)" : JSON.stringify(data, null, 2);
    // Show the furthest security check reached, based on the API response status.
    const stage = status === 400 ? 1
      : (status === 401 || status === 429) ? 2
      : (status === 403 || status === 404) ? 3
      : path === "/register" ? 1
      : path === "/login" || path === "/logout" ? 2 : 3;
    showFlowStage(stage, { error: status >= 400, complete: status < 400 });
    backendState.textContent = status < 400 ? "SUCCESS" : "BLOCKED";
    backendState.closest(".live-badge").classList.remove("is-busy");
    if (authenticated && status === 401) {
      sessionToken = null;
      updateSession("");
    }
    return { response, data };
  } catch (error) {
    row.querySelector(".activity-code").textContent = "ERR";
    row.querySelector(".activity-code").className = "activity-code failure";
    responseStatus.textContent = "NETWORK ERROR";
    responseStatus.className = "status-pill status-error";
    responseBody.textContent = JSON.stringify({ error: "Could not reach the API", message: error.message }, null, 2);
    showFlowStage(0, { error: true });
    backendState.textContent = "OFFLINE";
    backendState.closest(".live-badge").classList.remove("is-busy");
    return null;
  }
}

function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function withBusyButton(event, action) {
  const button = event.submitter || event.currentTarget.querySelector('[type="submit"]');
  if (!button || button.classList.contains("is-pending")) return null;
  button.classList.add("is-pending");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    return await action();
  } finally {
    button.classList.remove("is-pending");
    button.removeAttribute("aria-busy");
    // Keep protected actions disabled when a request expired or cleared the session.
    button.disabled = button.hasAttribute("data-auth-action") && !sessionToken;
  }
}

function updateSession(username) {
  const banner = $("#session-banner");
  const text = $("#session-text");
  const logout = $("#logout-button");
  const authenticated = Boolean(sessionToken);
  banner.classList.toggle("signed-in", authenticated);
  banner.classList.toggle("signed-out", !authenticated);
  text.textContent = authenticated
    ? `Signed in as ${username}. Bearer session verified by the API on protected requests.`
    : "No active session. Log in to create or read records.";
  logout.hidden = !authenticated;
  document.querySelectorAll("[data-auth-action]").forEach((button) => {
    button.disabled = !authenticated;
  });
}

$("#register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const result = await withBusyButton(event, () => sendRequest("POST", "/register", "Validate fields → scrypt password → save user role as user", formData(form)));
  if (result?.response.ok) form.reset();
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = formData(event.currentTarget);
  const result = await withBusyButton(event, () => sendRequest("POST", "/login", "Check account lockout → verify scrypt hash → issue opaque session", fields));
  if (result?.response.ok && result.data?.token) {
    sessionToken = result.data.token;
    updateSession(fields.username);
    event.currentTarget.reset();
  }
});

$("#create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await withBusyButton(event, () => sendRequest("POST", "/records", "Verify bearer session → validate fields → assign owner from session", formData(event.currentTarget), true));
  if (result?.response.ok && result.data?.id) {
    $("#record-id").value = result.data.id;
    event.currentTarget.reset();
  }
});

$("#read-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = $("#record-id").value.trim();
  if (!id) return;
  await withBusyButton(event, () => sendRequest("GET", `/records/${encodeURIComponent(id)}`, "Verify bearer session → load record → check owner or server-side admin role", undefined, true));
});

$("#logout-button").addEventListener("click", async () => {
  if (!sessionToken) return;
  const result = await sendRequest("POST", "/logout", "Revoke the server-side session and clear this tab token", undefined, true);
  if (result?.response.ok) {
    sessionToken = null;
    updateSession("");
  }
});

updateSession("");
