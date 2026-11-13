const STATUSES = ["Submitted", "Under Review", "Approved", "Issued"];
let currentApps = [];

function getToken() {
  return sessionStorage.getItem("bt_token");
}

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function getStaticUsers() {
  const saved = localStorage.getItem("bt_users");
  if (!saved) return [];
  const users = JSON.parse(saved);
  if (!Array.isArray(users)) throw new Error("Saved account data is invalid.");
  return users;
}

function getStaticSession() {
  const saved = sessionStorage.getItem("bt_static_session");
  if (!saved) return null;
  let session;
  try { session = JSON.parse(saved); } catch { session = null; }
  const valid = session && getStaticUsers().some((user) => normalize(user.username) === normalize(session.username) && user.role === session.role);
  if (!valid) {
    sessionStorage.removeItem("bt_token");
    sessionStorage.removeItem("bt_static_session");
    return null;
  }
  return session;
}

function makeSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashStaticPassword(password, salt) {
  if (!crypto.subtle) throw new Error("Secure browser authentication requires HTTPS or the Node server.");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const saltBytes = Uint8Array.from(salt.match(/.{2}/g), (part) => parseInt(part, 16));
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: 150000, hash: "SHA-256" }, key, 256);
  return Array.from(new Uint8Array(bits), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validateAccount(body) {
  const name = String(body.name || "").trim();
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!name || name.length > 120) throw new Error("Enter a full name of up to 120 characters.");
  if (!/^[A-Za-z0-9._-]{3,64}$/.test(username)) throw new Error("Username must be 3-64 characters using letters, numbers, dots, underscores or hyphens.");
  if (password.length < 6 || password.length > 1024) throw new Error("Password must be at least 6 characters.");
  return { name, username, password };
}

function createStaticSession(user) {
  const token = "static-" + Array.from(crypto.getRandomValues(new Uint8Array(24)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const publicUser = { name: user.name, username: user.username, role: user.role };
  sessionStorage.setItem("bt_token", token);
  sessionStorage.setItem("bt_static_session", JSON.stringify(publicUser));
  return { token, user: publicUser };
}

async function createStaticUser(body, role) {
  const account = validateAccount(body);
  let users = getStaticUsers();
  if (role === "admin" && users.some((user) => user.role === "admin")) throw new Error("An administrator account already exists.");
  if (users.some((user) => normalize(user.username) === normalize(account.username))) throw new Error("That username is already taken.");
  const salt = makeSalt();
  const passwordHash = await hashStaticPassword(account.password, salt);
  users = getStaticUsers();
  if (role === "admin" && users.some((user) => user.role === "admin")) throw new Error("An administrator account already exists.");
  if (users.some((user) => normalize(user.username) === normalize(account.username))) throw new Error("That username is already taken.");
  const user = { name: account.name, username: account.username, role, salt, passwordHash };
  users.push(user);
  localStorage.setItem("bt_users", JSON.stringify(users));
  return createStaticSession(user);
}

async function getStaticApplications() {
  const saved = localStorage.getItem("bt_applications");
  if (!saved) return [];
  const applications = JSON.parse(saved);
  if (!Array.isArray(applications)) throw new Error("Saved application data is invalid.");
  return applications;
}

async function staticApi(requestPath, options = {}) {
  const url = new URL(requestPath, window.location.href);
  const method = String(options.method || "GET").toUpperCase();
  const body = options.body ? JSON.parse(options.body) : {};
  if (url.pathname.endsWith("/api/bootstrap") && method === "GET") return { setupRequired: !getStaticUsers().some((user) => user.role === "admin") };
  if (url.pathname.endsWith("/api/setup") && method === "POST") return createStaticUser(body, "admin");
  if (url.pathname.endsWith("/api/register") && method === "POST") return createStaticUser(body, "applicant");
  if (url.pathname.endsWith("/api/login") && method === "POST") {
    const user = getStaticUsers().find((item) => normalize(item.username) === normalize(body.username));
    if (!user || await hashStaticPassword(String(body.password || ""), user.salt) !== user.passwordHash) throw new Error("Invalid username or password.");
    return createStaticSession(user);
  }

  const session = getStaticSession();
  if (!session) throw new Error("Authentication required.");
  if (url.pathname.endsWith("/api/session") && method === "GET") return { user: session };
  if (url.pathname.endsWith("/api/logout") && method === "POST") {
    sessionStorage.removeItem("bt_token");
    sessionStorage.removeItem("bt_static_session");
    return { ok: true };
  }
  const applications = await getStaticApplications();
  if (url.pathname.endsWith("/api/applications") && method === "POST") {
    if (session.role !== "applicant") throw new Error("Only applicants can submit applications.");
    const required = ["childName", "dob", "gender", "birthPlace", "parentName", "parentId", "parentPhone"];
    if (required.some((field) => !String(body[field] || "").trim())) throw new Error("All required application fields must be provided.");
    const duplicate = applications.find((app) => normalize(app.childName) === normalize(body.childName) && app.dob === body.dob && String(app.parentId).trim() === String(body.parentId).trim());
    if (duplicate) throw new Error(`Duplicate application already exists (${duplicate.id}, status: ${duplicate.status}).`);
    const highest = applications.reduce((max, app) => Math.max(max, Number(/^BT-(\d+)$/i.exec(app.id)?.[1] || 0)), 0);
    const application = { id: `BT-${String(highest + 1).padStart(4, "0")}`, childName: String(body.childName).trim(), dob: body.dob, gender: body.gender, birthPlace: String(body.birthPlace).trim(), parentName: String(body.parentName).trim(), parentId: String(body.parentId).trim(), parentPhone: String(body.parentPhone).trim(), submittedBy: session.username, dateSubmitted: new Date().toISOString().slice(0, 10), status: "Submitted" };
    applications.push(application);
    localStorage.setItem("bt_applications", JSON.stringify(applications));
    return { application };
  }
  const statusMatch = /\/api\/applications\/([^/]+)\/status$/.exec(url.pathname);
  if (statusMatch && method === "PATCH") {
    if (session.role !== "clerk" && session.role !== "admin") throw new Error("Only staff can update application status.");
    if (!STATUSES.includes(body.status)) throw new Error("Invalid status.");
    const application = applications.find((item) => item.id === decodeURIComponent(statusMatch[1]));
    if (!application) throw new Error("Application not found.");
    application.status = body.status;
    localStorage.setItem("bt_applications", JSON.stringify(applications));
    return { application };
  }
  if (url.pathname.endsWith("/api/applications") && method === "GET") {
    const visible = session.role === "clerk" || session.role === "admin" ? applications : applications.filter((app) => app.submittedBy === session.username);
    const search = normalize(url.searchParams.get("q"));
    const filtered = search ? visible.filter((app) => normalize(app.id) === search || normalize(app.parentId) === search || normalize(app.childName).includes(search)) : visible;
    return { applications: filtered };
  }
  throw new Error("API endpoint not found.");
}

async function api(requestPath, options = {}) {
  if (window.location.hostname.endsWith("github.io") || window.location.protocol === "file:") return staticApi(requestPath, options);
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (getToken()) headers.Authorization = `Bearer ${getToken()}`;
  const response = await fetch(requestPath, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed.");
  return data;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char]));
}

function statusPill(status) {
  const className = status.toLowerCase().replace(/\s+/g, "-");
  return `<span class="status-pill ${className}">${escapeHtml(status)}</span>`;
}

function initLoginPage() {
  const form = document.getElementById("loginForm");
  if (!form) return;
  const nameGroup = document.getElementById("nameGroup");
  const fullName = document.getElementById("fullName");
  const username = document.getElementById("username");
  const password = document.getElementById("password");
  const switchElement = document.getElementById("accountSwitch");
  const errorElement = document.getElementById("loginError");
  let mode = "login";
  function draw() {
    document.getElementById("loginTitle").textContent = { login: "Log in", setup: "Set up administrator account", register: "Create member account" }[mode];
    nameGroup.style.display = mode === "login" ? "none" : "block";
    fullName.required = mode !== "login";
    password.autocomplete = mode === "login" ? "current-password" : "new-password";
    document.getElementById("submitButton").textContent = mode === "login" ? "Sign in" : mode === "setup" ? "Create administrator account" : "Create member account";
    switchElement.innerHTML = mode === "register" ? '<a id="backToLogin" href="#login">Back to log in</a>' : '<a id="createAccount" href="#register">Create an account</a>';
    const createLink = document.getElementById("createAccount");
    if (createLink) createLink.onclick = (event) => { event.preventDefault(); mode = "register"; draw(); };
    const backLink = document.getElementById("backToLogin");
    if (backLink) backLink.onclick = async (event) => { event.preventDefault(); try { const state = await api("/api/bootstrap"); mode = state.setupRequired ? "setup" : "login"; draw(); } catch (error) { errorElement.textContent = error.message; } };
  }
  async function start() {
    if (getToken()) {
      try { const result = await api("/api/session"); if (result.user) { window.location.href = "birthtrack-dashboard.html"; return; } }
      catch { sessionStorage.removeItem("bt_token"); sessionStorage.removeItem("bt_static_session"); }
    }
    const state = await api("/api/bootstrap");
    mode = state.setupRequired ? "setup" : "login";
    draw();
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorElement.textContent = "";
    const credentials = { username: username.value.trim(), password: password.value };
    if (mode !== "login") credentials.name = fullName.value.trim();
    const endpoint = mode === "setup" ? "/api/setup" : mode === "register" ? "/api/register" : "/api/login";
    try {
      const result = await api(endpoint, { method: "POST", body: JSON.stringify(credentials) });
      sessionStorage.setItem("bt_token", result.token);
      window.location.href = "birthtrack-dashboard.html";
    } catch (error) { errorElement.textContent = error.message; }
  });
  start().catch((error) => { errorElement.textContent = error.message; });
}
async function initDashboard() {
  const wrapper = document.querySelector(".dash-wrapper");
  if (!wrapper) return;

  const session = getToken() ? (await api("/api/session").catch(() => null))?.user : null;
  if (!session) {
    sessionStorage.removeItem("bt_token");
    window.location.href = "birthtrack-login.html";
    return;
  }

  const isStaff = session.role === "clerk" || session.role === "admin";
  const roleLabels = {
    applicant: "Applicant (Parent)",
    clerk: "Registration Clerk",
    admin: "System Administrator",
  };
  document.getElementById("roleBadge").textContent = roleLabels[session.role];
  document.getElementById("applicationsTitle").textContent = isStaff ? "all applications" : "my applications";
  if (!isStaff) document.getElementById("actionHeader").style.display = "none";

  async function loadApps(search = "") {
    const query = search ? `?q=${encodeURIComponent(search)}` : "";
    currentApps = (await api(`/api/applications${query}`)).applications;
    return currentApps;
  }

  function renderOverview(applications = currentApps) {
    const count = (status) => applications.filter((application) => application.status === status).length;
    document.getElementById("countSubmitted").textContent = count("Submitted");
    document.getElementById("countReview").textContent = count("Under Review");
    document.getElementById("countApproved").textContent = count("Approved");
    document.getElementById("countIssued").textContent = count("Issued");

    const body = document.getElementById("recentBody");
    body.innerHTML = applications.length ? "" : '<tr class="empty-row"><td colspan="4">No applications yet.</td></tr>';
    applications.slice().reverse().slice(0, 5).forEach((application) => {
      const row = document.createElement("tr");
      row.innerHTML = `<td>${escapeHtml(application.id)}</td><td>${escapeHtml(application.childName)}</td><td>${escapeHtml(application.dateSubmitted)}</td><td>${statusPill(application.status)}</td>`;
      body.appendChild(row);
    });
  }

  function renderApplications(applications = currentApps) {
    const body = document.getElementById("applicationsBody");
    body.innerHTML = "";
    const columns = isStaff ? 6 : 5;
    if (!applications.length) {
      body.innerHTML = `<tr class="empty-row"><td colspan="${columns}">No applications found.</td></tr>`;
      return;
    }
    applications.forEach((application) => {
      const index = STATUSES.indexOf(application.status);
      const nextStatus = STATUSES[index + 1];
      const action = isStaff
        ? `<td class="actions">${nextStatus ? `<button class="link-btn" data-id="${escapeHtml(application.id)}" data-next="${nextStatus}">mark ${nextStatus.toLowerCase()}</button>` : '<span class="text-muted">complete</span>'}</td>`
        : "";
      const row = document.createElement("tr");
      row.innerHTML = `<td>${escapeHtml(application.id)}</td><td>${escapeHtml(application.childName)}</td><td>${escapeHtml(application.parentId)}</td><td>${escapeHtml(application.dateSubmitted)}</td><td>${statusPill(application.status)}</td>${action}`;
      body.appendChild(row);
    });
  }

  const panels = document.querySelectorAll(".panel");
  const navButtons = document.querySelectorAll(".nav-btn");
  async function refreshPanel(name) {
    try {
      await loadApps();
      if (name === "overview") renderOverview();
      if (name === "applications") renderApplications();
    } catch (error) {
      alert(error.message);
    }
  }
  function showPanel(name) {
    panels.forEach((panel) => panel.classList.toggle("active", panel.id === `panel-${name}`));
    navButtons.forEach((button) => button.classList.toggle("active", button.dataset.panel === name));
    refreshPanel(name);
  }
  navButtons.forEach((button) => button.addEventListener("click", () => showPanel(button.dataset.panel)));
  document.querySelectorAll("[data-goto]").forEach((button) => button.addEventListener("click", () => showPanel(button.dataset.goto)));

  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" }).catch(() => {});
    sessionStorage.removeItem("bt_token");
    window.location.href = "birthtrack-login.html";
  });

  document.getElementById("applicationsBody").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-next]");
    if (!button) return;
    try {
      await api(`/api/applications/${encodeURIComponent(button.dataset.id)}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status: button.dataset.next }),
      });
      await loadApps();
      renderApplications();
      renderOverview();
    } catch (error) {
      alert(error.message);
    }
  });

  const applicationForm = document.getElementById("appForm");
  const duplicateWarning = document.getElementById("duplicateWarning");
  applicationForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    duplicateWarning.classList.remove("active");
    const payload = {
      childName: document.getElementById("childName").value,
      dob: document.getElementById("childDob").value,
      gender: document.getElementById("childGender").value,
      birthPlace: document.getElementById("birthPlace").value,
      parentName: document.getElementById("parentName").value,
      parentId: document.getElementById("parentId").value,
      parentPhone: document.getElementById("parentPhone").value,
    };
    try {
      await api("/api/applications", { method: "POST", body: JSON.stringify(payload) });
      applicationForm.reset();
      alert("Application submitted successfully.");
      showPanel("applications");
    } catch (error) {
      duplicateWarning.textContent = error.message;
      duplicateWarning.classList.add("active");
    }
  });

  async function runSearch() {
    const term = document.getElementById("searchInput").value.trim();
    const body = document.getElementById("searchBody");
    body.innerHTML = "";
    if (!term) {
      body.innerHTML = '<tr class="empty-row"><td colspan="4">Enter a search term above.</td></tr>';
      return;
    }
    try {
      const applications = await loadApps(term);
      if (!applications.length) {
        body.innerHTML = '<tr class="empty-row"><td colspan="4">No matching record found.</td></tr>';
        return;
      }
      applications.forEach((application) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${escapeHtml(application.id)}</td><td>${escapeHtml(application.childName)}</td><td>${escapeHtml(application.parentId)}</td><td>${statusPill(application.status)}</td>`;
        body.appendChild(row);
      });
    } catch (error) {
      body.innerHTML = `<tr class="empty-row"><td colspan="4">${escapeHtml(error.message)}</td></tr>`;
    }
  }
  document.getElementById("searchBtn").addEventListener("click", runSearch);
  document.getElementById("searchInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") runSearch();
  });

  await refreshPanel("overview");
}

document.addEventListener("DOMContentLoaded", () => {
  initLoginPage();
  initDashboard();
});
