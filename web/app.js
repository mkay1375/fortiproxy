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
let status = null;
let reachable = false;
let submitting = false;

const descriptions = {
  disconnected: ['Disconnected', 'Ready when you are', 'Enter your VPN settings and connect to enable the local proxies.'],
  connecting: ['Connecting', 'Establishing your tunnel', 'Authenticating with the gateway. Proxy traffic stays blocked until the VPN is ready.'],
  connected: ['Connected', 'Your tunnel is ready', 'Use a local proxy address below in the apps you want to route through the VPN.'],
  error: ['Connection failed', 'Could not connect', 'Check your connection settings and try again.'],
};

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

function render() {
  const state = reachable && status ? status.state : 'unknown';
  const active = state === 'connecting' || state === 'connected';
  const description = descriptions[state];
  badge.dataset.state = state;
  tunnel.dataset.state = state;
  statusLabel.textContent = description ? description[0] : 'Unavailable';
  statusTitle.textContent = description ? description[1] : 'Connection manager unavailable';
  statusMessage.textContent = description ? (status.message || description[2]) : 'Cannot read the VPN status. Check that the container is running; this page will retry automatically.';
  fields.disabled = submitting || active || !reachable;
  connectButton.disabled = submitting || active || !reachable;
  connectButton.querySelector('span').textContent = submitting ? 'Please wait…' : state === 'connecting' ? 'Connecting…' : state === 'connected' ? 'VPN connected' : 'Connect VPN';
  disconnectButton.hidden = !active;
  disconnectButton.disabled = submitting || !reachable;
  availability.textContent = state === 'connected' ? 'Ready to use' : state === 'unknown' ? 'Status unavailable' : 'Waiting for VPN';
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

async function refresh() {
  if (submitting) return;
  try {
    const result = await request('/api/status');
    if (!(result.state in descriptions)) throw new Error('Invalid connection status.');
    status = result;
    reachable = true;
  } catch {
    reachable = false;
  }
  if (!submitting) render();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submitting || !reachable || !form.reportValidity()) return;
  const data = Object.fromEntries(new FormData(form));
  data.port = Number(data.port);
  for (const key of ['name', 'host', 'username', 'realm', 'trusted_cert']) data[key] = data[key].trim();
  submitting = true;
  showError('');
  render();
  try {
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
void refresh();
setInterval(refresh, 2000);
setInterval(updateTime, 1000);
