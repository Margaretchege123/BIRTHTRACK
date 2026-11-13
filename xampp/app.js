let csrfToken = '';
const STAGES = ['Submitted', 'Under Review', 'Approved', 'Issued'];
const PAGES = { applicant: 'applicant.html', clerk: 'clerk.html', admin: 'admin.html' };

const esc = value => String(value).replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

async function api(action, method = 'GET', body = null, id = null) {
  let url = 'api.php?action=' + encodeURIComponent(action);
  if (id !== null) url += '&id=' + encodeURIComponent(id);
  const headers = {};
  const options = { method, credentials: 'same-origin', headers };
  if (body !== null) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;

  const response = await fetch(url, options);
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error('The server returned an invalid response. Check that Apache and PHP are running.');
  }
  if (!response.ok) throw new Error(result.error || 'The request could not be completed.');
  return result;
}

async function initializeApi() {
  const state = await api('bootstrap');
  csrfToken = state.csrfToken;
  return state;
}

async function guard(role) {
  await initializeApi();
  const result = await api('me');
  if (!result.user || result.user.role !== role) {
    location.replace('login.html');
    throw new Error('Please log in with an account that has access to this page.');
  }
  document.getElementById('bar').innerHTML =
    '<b>BirthTrack System</b><span>' + esc(result.user.name) + ' (' + esc(role) +
    ') <button onclick="logout()">Log out</button></span>';
  return result.user;
}

async function logout() {
  await api('logout', 'POST', {});
  location.replace('login.html');
}

async function fetchUsers() {
  return (await api('users')).users;
}

async function addUser(name, username, password, role) {
  try {
    await api('users', 'POST', { name, username, password, role });
    return '';
  } catch (error) {
    return error.message;
  }
}

async function deleteUser(id) {
  await api('users', 'DELETE', {}, id);
}

async function apps() {
  return (await api('applications')).applications;
}

async function addApp(application) {
  return api('applications', 'POST', application);
}

async function updateStatus(id, status) {
  await api('applications', 'PATCH', { status }, id);
}

function reportError(error) {
  const message = error instanceof Error ? error.message : String(error);
  const target = document.getElementById('pageError') || document.getElementById('m');
  if (target) {
    target.className = 'err';
    target.textContent = message;
  } else {
    console.error(message);
  }
}

function appRows(list, clerk) {
  return list.map(application => '<tr><td>' + esc(application.id) + '</td><td>' +
    esc(application.child) + '</td><td>' + esc(application.parent) + '</td><td>' +
    esc(application.nid) + '</td><td>' + esc(application.date) + '</td><td>' +
    (clerk
      ? '<select data-app-id="' + esc(application.id) + '">' +
        STAGES.map(stage => '<option' + (stage === application.status ? ' selected' : '') +
          '>' + esc(stage) + '</option>').join('') + '</select>'
      : esc(application.status)) + '</td></tr>').join('') ||
    '<tr><td colspan="6">No applications found.</td></tr>';
}

const HEAD = '<thead><tr><th>ID</th><th>Child</th><th>Parent</th>' +
  '<th>Parent National ID</th><th>Date</th><th>Status</th></tr></thead>';
