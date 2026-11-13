const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = __dirname;
const DATA_FILE = path.join(__dirname, "data.json");
const USERS_FILE = path.join(__dirname, "users.json");
const sessions = new Map();
const STATUSES = ["Submitted", "Under Review", "Approved", "Issued"];

function readApplications() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, "[]\n", { mode: 0o600 });
    return [];
  }
  const applications = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  if (!Array.isArray(applications)) throw new Error("Application data is invalid.");
  return applications;
}

function writeApplications(applications) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(applications, null, 2), { mode: 0o600 });
}

function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  if (!Array.isArray(users)) throw new Error("Account data is invalid.");
  return users;
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), { mode: 0o600 });
}

function send(res, status, value) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(JSON.stringify(value));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        const error = new Error("Request body too large.");
        error.statusCode = 413;
        reject(error);
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { const error = new Error("Invalid JSON."); error.statusCode = 400; reject(error); }
    });
    req.on("error", reject);
  });
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function tokenFrom(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function sessionFor(req) {
  return sessions.get(tokenFrom(req)) || null;
}

function requireAuth(req, res) {
  const session = sessionFor(req);
  if (!session) {
    send(res, 401, { error: "Authentication required." });
    return null;
  }
  return session;
}

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function nextId(applications) {
  const highest = applications.reduce((max, app) => {
    const match = /^BT-(\d+)$/i.exec(app.id);
    return match ? Math.max(max, Number(match[1])) : max;
  }, 0);
  return `BT-${String(highest + 1).padStart(4, "0")}`;
}

function publicUser(user) {
  return { name: user.name, username: user.username, role: user.role };
}

function validateAccount(body) {
  const name = String(body.name || "").trim();
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!name || name.length > 120) throw httpError(400, "Enter a full name of up to 120 characters.");
  if (!/^[A-Za-z0-9._-]{3,64}$/.test(username)) throw httpError(400, "Username must be 3-64 characters using letters, numbers, dots, underscores or hyphens.");
  if (password.length < 6 || password.length > 1024) throw httpError(400, "Password must be at least 6 characters.");
  return { name, username, password };
}

function createUser(body, role) {
  const account = validateAccount(body);
  const users = readUsers();
  if (users.some((user) => normalize(user.username) === normalize(account.username))) throw httpError(409, "That username is already taken.");
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = crypto.scryptSync(account.password, salt, 64).toString("hex");
  const user = { name: account.name, username: account.username, role, salt, passwordHash };
  users.push(user);
  writeUsers(users);
  return user;
}

function verifyPassword(password, user) {
  if (!user || typeof user.salt !== "string" || typeof user.passwordHash !== "string") return false;
  const expected = Buffer.from(user.passwordHash, "hex");
  if (expected.length !== 64) return false;
  const actual = crypto.scryptSync(String(password || ""), user.salt, expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

function issueSession(user, res) {
  const token = crypto.randomBytes(32).toString("hex");
  const session = publicUser(user);
  sessions.set(token, session);
  return send(res, 200, { token, user: session });
}

async function api(req, res, pathname, url) {
  const method = req.method;
  if (pathname === "/api/bootstrap" && method === "GET") return send(res, 200, { setupRequired: !readUsers().some((user) => user.role === "admin") });
  if (pathname === "/api/login" && method === "POST") {
    const body = await readJson(req);
    const user = readUsers().find((item) => normalize(item.username) === normalize(body.username));
    if (!verifyPassword(body.password, user)) return send(res, 401, { error: "Invalid username or password." });
    return issueSession(user, res);
  }
  if (pathname === "/api/setup" && method === "POST") {
    const body = await readJson(req);
    if (readUsers().some((user) => user.role === "admin")) return send(res, 409, { error: "An administrator account already exists." });
    return issueSession(createUser(body, "admin"), res);
  }
  if (pathname === "/api/register" && method === "POST") {
    const body = await readJson(req);
    return issueSession(createUser(body, "applicant"), res);
  }

  const session = requireAuth(req, res);
  if (!session) return;
  if (pathname === "/api/session" && method === "GET") return send(res, 200, { user: session });
  if (pathname === "/api/logout" && method === "POST") {
    sessions.delete(tokenFrom(req));
    return send(res, 200, { ok: true });
  }
  if (pathname === "/api/applications" && method === "GET") {
    const applications = readApplications();
    const visible = session.role === "clerk" || session.role === "admin" ? applications : applications.filter((app) => app.submittedBy === session.username);
    const search = normalize(url.searchParams.get("q"));
    const filtered = search ? visible.filter((app) => normalize(app.id) === search || normalize(app.parentId) === search || normalize(app.childName).includes(search)) : visible;
    return send(res, 200, { applications: filtered });
  }
  if (pathname === "/api/applications" && method === "POST") {
    if (session.role !== "applicant") return send(res, 403, { error: "Only applicants can submit applications." });
    const body = await readJson(req);
    const required = ["childName", "dob", "gender", "birthPlace", "parentName", "parentId", "parentPhone"];
    if (required.some((field) => !String(body[field] || "").trim())) return send(res, 400, { error: "All required application fields must be provided." });
    const applications = readApplications();
    const duplicate = applications.find((app) => normalize(app.childName) === normalize(body.childName) && app.dob === body.dob && String(app.parentId).trim() === String(body.parentId).trim());
    if (duplicate) return send(res, 409, { error: `Duplicate application already exists (${duplicate.id}, status: ${duplicate.status}).` });
    const application = { id: nextId(applications), childName: String(body.childName).trim(), dob: body.dob, gender: body.gender, birthPlace: String(body.birthPlace).trim(), parentName: String(body.parentName).trim(), parentId: String(body.parentId).trim(), parentPhone: String(body.parentPhone).trim(), submittedBy: session.username, dateSubmitted: new Date().toISOString().slice(0, 10), status: "Submitted" };
    applications.push(application);
    writeApplications(applications);
    return send(res, 201, { application });
  }
  const statusMatch = /^\/api\/applications\/([^/]+)\/status$/.exec(pathname);
  if (statusMatch && method === "PATCH") {
    if (session.role !== "clerk" && session.role !== "admin") return send(res, 403, { error: "Only staff can update application status." });
    const { status } = await readJson(req);
    if (!STATUSES.includes(status)) return send(res, 400, { error: "Invalid status." });
    const applications = readApplications();
    const index = applications.findIndex((app) => app.id === decodeURIComponent(statusMatch[1]));
    if (index === -1) return send(res, 404, { error: "Application not found." });
    applications[index].status = status;
    writeApplications(applications);
    return send(res, 200, { application: applications[index] });
  }
  return send(res, 404, { error: "API endpoint not found." });
}

const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8" };
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  try {
    if (url.pathname.startsWith("/api/")) return await api(req, res, url.pathname, url);
    const decoded = decodeURIComponent(url.pathname);
    const relative = decoded === "/" ? "birthtrack-login.html" : decoded.slice(1);
    const file = path.resolve(PUBLIC_DIR, relative);
    if (!file.startsWith(PUBLIC_DIR + path.sep) || ["data.json", "users.json", ".env"].includes(path.basename(file)) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404);
      return res.end("Not found");
    }
    res.writeHead(200, { "Content-Type": contentTypes[path.extname(file)] || "application/octet-stream", "X-Content-Type-Options": "nosniff" });
    fs.createReadStream(file).pipe(res);
  } catch (error) {
    if (res.headersSent) return res.destroy();
    if (!error.statusCode || error.statusCode >= 500) console.error(error);
    return send(res, error.statusCode || 500, { error: error.statusCode ? error.message : "Server error." });
  }
});
server.listen(PORT, "0.0.0.0", () => console.log(`BirthTrack is running at http://localhost:${PORT}`));