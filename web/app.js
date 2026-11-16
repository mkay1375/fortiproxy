'use strict';

const form = document.querySelector('#connection-form');
const fields = document.querySelector('#connection-fields');
const connectButton = document.querySelector('#connect-button');
const disconnectButton = document.querySelector('#disconnect-button');
const errorBox = document.querySelector('#form-error');
const password = document.querySelector('#password');
const otp = document.querySelector('#otp');
const badge = document.querySelector('#status-badge');
const statusLabel = document.querySelector('#status-label');
const statusTitle = document.querySelector('#status-title');
const statusMessage = document.querySelector('#status-message');
const tunnel = document.querySelector('#tunnel');
const connectionTime = document.querySelector('#connection-time');
const availability = document.querySelector('#proxy-availability');
const gatewayButton = document.querySelector('#test-gateway');
const gatewayMessage = document.querySelector('#gateway-test-message');
let testingGateway = false;
let gatewayVersion = 0;
const profileMessage = document.querySelector('#profile-message');
const profileFields = ['name', 'host', 'port', 'username', 'realm', 'trusted_cert', 'ignore_cert', 'otp_mode'];
let profileReady = false;
let saveTimer;
let saveQueue = Promise.resolve();
let saveVersion = 0;
let status = null;
let reachable = false;
let submitting = false;
let refreshVersion = 0;

const descriptions = {
  disconnected: ['Disconnected', 'Ready when you are', 'Enter your VPN settings and connect to enable the local proxies.'],
  connecting: ['Connecting', 'Establishing your tunnel', 'Authenticating with the gateway. Proxy traffic stays blocked until the VPN is ready.'],
  disconnecting: ['Disconnecting', 'Closing your tunnel', 'Stopping the VPN and clearing the connection credentials.'],
  connected: ['Connected', 'Your tunnel is ready', 'Use a local proxy address below in the apps you want to route through the VPN.'],
  error: ['Connection failed', 'Could not connect', 'Check your connection settings and try again.'],
};

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

function render() {
  const state = reachable && status ? status.state : 'unknown';
  const active = state === 'connecting' || state === 'connected' || state === 'disconnecting';
  const description = descriptions[state];
  badge.dataset.state = state;
  tunnel.dataset.state = state;
  statusLabel.textContent = description ? description[0] : 'Unavailable';
  statusTitle.textContent = description ? description[1] : 'Connection manager unavailable';
  statusMessage.textContent = description ? (status.message || description[2]) : 'Cannot read the VPN status. Check that the container is running; this page will retry automatically.';
  fields.disabled = submitting || active || !reachable || !profileReady;
  connectButton.disabled = submitting || active || !reachable || !profileReady;
  connectButton.querySelector('span').textContent = submitting ? 'Please wait…' : state === 'connecting' ? 'Connecting…' : state === 'connected' ? 'VPN connected' : state === 'disconnecting' ? 'Disconnecting…' : 'Connect VPN';
  disconnectButton.hidden = !active;
  disconnectButton.disabled = submitting || !reachable || state === 'disconnecting';
  disconnectButton.textContent = state === 'disconnecting' ? 'Disconnecting…' : 'Disconnect VPN';
  availability.textContent = state === 'connected' ? 'Ready to use' : state === 'unknown' ? 'Status unavailable' : 'Waiting for VPN';
  gatewayButton.disabled = testingGateway || submitting || active || !reachable || !profileReady;
  updateTime();
}

function updateTime() {
  const started = status && status.connected_at ? Date.parse(status.connected_at) : NaN;
  const show = reachable && status && status.state === 'connected' && Number.isFinite(started);
  connectionTime.hidden = !show;
  if (show) {
    const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
    const minutes = Math.floor(seconds / 60);
    connectionTime.textContent = minutes >= 60 ? `Connected for ${Math.floor(minutes / 60)}h ${minutes % 60}m` : minutes > 0 ? `Connected for ${minutes}m ${seconds % 60}s` : `Connected for ${seconds}s`;
  }
}

async function request(path, data) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(path, {
      method: data === undefined ? 'GET' : 'POST',
      headers: data === undefined ? {} : {'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1'},
      body: data === undefined ? undefined : JSON.stringify(data),
      credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    return result;
  } finally {
    clearTimeout(timeout);
  }
}

function syncAuthenticationOptions() {
  const ignore = form.elements.namedItem('ignore_cert').checked;
  form.elements.namedItem('trusted_cert').disabled = ignore;
  document.querySelector('#certificate-warning').hidden = !ignore;
  document.querySelector('#otp-note').textContent = form.elements.namedItem('otp_mode').value === 'append'
    ? 'The code is appended directly to your password, with no separator.'
    : 'The code is sent separately when the gateway requests a challenge.';
}
for (const key of ['ignore_cert', 'otp_mode']) {
  form.elements.namedItem(key).addEventListener('change', syncAuthenticationOptions);
}

function saveProfile() {
  clearTimeout(saveTimer);
  const data = {};
  for (const key of profileFields) {
    const input = form.elements.namedItem(key);
    data[key] = input.type === 'checkbox' ? input.checked : key === 'port' ? Number(input.value) : input.value.trim();
  }
  const version = ++saveVersion;
  profileMessage.textContent = 'Saving settings…';
  // Serialize writes so a slower older request cannot replace newer settings.
  const pending = saveQueue.then(() => request('/api/profile', data));
  saveQueue = pending.catch(() => {});
  return pending.then(() => {
    if (version === saveVersion) profileMessage.textContent = 'Settings saved on disk. Changes save automatically.';
  }, error => {
    if (version === saveVersion) profileMessage.textContent = `Settings not saved: ${error.message}`;
    throw error;
  });
}

for (const key of profileFields) {
  const input = form.elements.namedItem(key);
  input.addEventListener('input', () => {
    if (!profileReady) return;
    clearTimeout(saveTimer);
    profileMessage.textContent = 'Unsaved changes…';
    saveTimer = setTimeout(() => { void saveProfile().catch(() => {}); }, 400);
  });
  input.addEventListener('change', () => {
    if (profileReady) void saveProfile().catch(() => {});
  });
}

async function restoreProfile() {
  try {
    const profile = await request('/api/profile');
    for (const key of profileFields) {
      if (Object.hasOwn(profile, key)) {
        const input = form.elements.namedItem(key);
        if (input.type === 'checkbox') input.checked = profile[key];
        else input.value = profile[key];
      }
    }
    syncAuthenticationOptions();
    profileReady = true;
    profileMessage.textContent = Object.keys(profile).length ? 'Saved settings restored. Changes save automatically.' : 'Connection settings save automatically on disk.';
  } catch {
    profileMessage.textContent = 'Cannot load saved settings. Reload this page to retry.';
  }
  render();
}

async function refresh() {
  if (submitting) return;
  const version = ++refreshVersion;
  try {
    const result = await request('/api/status');
    if (!(result.state in descriptions)) throw new Error('Invalid connection status.');
    if (version !== refreshVersion || submitting) return;
    status = result;
    reachable = true;
  } catch {
    if (version !== refreshVersion || submitting) return;
    reachable = false;
  }
  if (!submitting) render();
}

gatewayButton.addEventListener('click', async () => {
  const host = form.elements.namedItem('host');
  const port = form.elements.namedItem('port');
  if (!host.reportValidity() || !port.reportValidity() || testingGateway) return;
  testingGateway = true;
  const version = ++gatewayVersion;
  gatewayMessage.textContent = 'Testing gateway TCP port…';
  gatewayMessage.dataset.result = '';
  render();
  try {
    const result = await request('/api/test-gateway', {host: host.value.trim(), port: Number(port.value)});
    if (version !== gatewayVersion) return;
    gatewayMessage.textContent = result.message;
    gatewayMessage.dataset.result = result.reachable ? 'success' : 'error';
  } catch (error) {
    if (version !== gatewayVersion) return;
    gatewayMessage.textContent = error.name === 'AbortError' ? 'Gateway test timed out. Try again.' : error.message;
    gatewayMessage.dataset.result = 'error';
  } finally {
    testingGateway = false;
    render();
  }
});
for (const key of ['host', 'port']) {
  form.elements.namedItem(key).addEventListener('input', () => {
    gatewayVersion += 1;
    gatewayMessage.textContent = '';
    gatewayMessage.dataset.result = '';
  });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submitting || !reachable || !form.reportValidity()) return;
  const data = Object.fromEntries(new FormData(form));
  data.port = Number(data.port);
  data.ignore_cert = form.elements.namedItem('ignore_cert').checked;
  for (const key of ['name', 'host', 'username', 'realm', 'trusted_cert']) data[key] = (data[key] || '').trim();
  submitting = true;
  refreshVersion += 1;
  showError('');
  render();
  try {
    await saveProfile();
    await request('/api/connect', data);
    password.value = '';
    otp.value = '';
  } catch (error) {
    showError(error.name === 'AbortError' ? 'The request timed out. Checking the connection status before you try again.' : error.message);
  } finally {
    submitting = false;
    await refresh();
  }
});

disconnectButton.addEventListener('click', async () => {
  if (submitting) return;
  submitting = true;
  refreshVersion += 1;
  showError('');
  render();
  try {
    await request('/api/disconnect', {});
  } catch (error) {
    showError(error.name === 'AbortError' ? 'Disconnect timed out. Checking the VPN status.' : error.message);
  } finally {
    submitting = false;
    await refresh();
  }
});

document.querySelector('#toggle-password').addEventListener('click', (event) => {
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  event.currentTarget.setAttribute('aria-pressed', String(show));
});

for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const address = document.getElementById(button.dataset.copy).textContent;
    try {
      await navigator.clipboard.writeText(address);
      button.textContent = 'Copied';
      document.querySelector('#copy-feedback').textContent = `Copied ${address}`;
      setTimeout(() => { button.textContent = 'Copy'; }, 1600);
    } catch {
      document.querySelector('#copy-feedback').textContent = 'Copy unavailable. Select the proxy address to copy it.';
      button.textContent = 'Select';
      const range = document.createRange();
      range.selectNodeContents(document.getElementById(button.dataset.copy));
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      setTimeout(() => { button.textContent = 'Copy'; }, 1600);
    }
  });
}

window.addEventListener('pagehide', () => { password.value = ''; otp.value = ''; });
async function poll() {
  await refresh();
  setTimeout(poll, 2000);
}
void restoreProfile().then(poll);
setInterval(updateTime, 1000);
