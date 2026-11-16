// Resolve the theme before styles paint. Only this preference uses localStorage.
(() => {
  const key = 'fortiproxy-theme';
  const choices = ['system', 'light', 'dark'];
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try {
    const saved = localStorage.getItem(key);
    if (choices.includes(saved)) preference = saved;
  } catch {}

  function apply() {
    const theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.themePreference = preference;
    document.documentElement.style.colorScheme = theme;
    const select = document.querySelector('#theme-select');
    if (select) select.value = preference;
  }

  function choose(value) {
    preference = choices.includes(value) ? value : 'system';
    try {
      if (preference === 'system') localStorage.removeItem(key);
      else localStorage.setItem(key, preference);
    } catch {}
    apply();
  }

  apply();
  media.addEventListener('change', () => { if (preference === 'system') apply(); });
  window.addEventListener('storage', event => {
    if (event.key === key || event.key === null) {
      preference = choices.includes(event.newValue) ? event.newValue : 'system';
      apply();
    }
  });
  document.addEventListener('DOMContentLoaded', () => {
    const select = document.querySelector('#theme-select');
    if (select) select.addEventListener('change', () => choose(select.value));
    apply();
  });
})();
