const root = document.documentElement;
root.classList.add('js');

// Mobile menu sheet.
const sheet = document.querySelector('[data-sheet]');
const sheetToggle = document.querySelector('[data-sheet-toggle]');
const sheetPanel = sheet?.querySelector('.nav-sheet-panel');
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
let sheetTimer = null;

function sheetFocusables() {
  return [...sheetPanel.querySelectorAll('a[href], button:not([disabled])')];
}

function openSheet() {
  if (!sheet || !sheetPanel || !sheet.hidden) return;
  clearTimeout(sheetTimer);
  sheet.hidden = false;
  root.classList.add('sheet-open');
  sheetToggle.setAttribute('aria-expanded', 'true');
  // Start from the closed position so the panel slides in.
  void sheetPanel.offsetWidth;
  sheet.classList.add('is-open');
  sheetFocusables()[0]?.focus();
}

function closeSheet({ restoreFocus = true } = {}) {
  if (!sheet || sheet.hidden) return;
  sheet.classList.remove('is-open');
  root.classList.remove('sheet-open');
  sheetToggle.setAttribute('aria-expanded', 'false');
  clearTimeout(sheetTimer);
  sheetTimer = setTimeout(() => { sheet.hidden = true; }, reducedMotion.matches ? 0 : 250);
  if (restoreFocus) sheetToggle.focus();
}

if (sheet && sheetToggle && sheetPanel) {
  sheetToggle.addEventListener('click', openSheet);
  sheet.addEventListener('click', (event) => {
    if (event.target.closest('[data-sheet-close]')) closeSheet();
    else if (event.target.closest('a[href]')) closeSheet({ restoreFocus: false });
  });
  sheet.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeSheet();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusables = sheetFocusables();
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  window.matchMedia('(min-width: 768px)').addEventListener('change', (event) => {
    if (event.matches) closeSheet({ restoreFocus: false });
  });
}

// Light and dark follow the device setting. The toggle overrides it for the
// page being viewed only; no choice is stored in the browser.
const themeToggles = document.querySelectorAll('[data-theme-toggle]');
const prefersLight = window.matchMedia('(prefers-color-scheme: light)');
const themeColors = { light: '#f6f7f9', dark: '#0b0d10' };

function activeTheme() {
  return root.dataset.theme || (prefersLight.matches ? 'light' : 'dark');
}

function syncThemeControls() {
  const theme = activeTheme();
  const label = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  themeToggles.forEach((toggle) => {
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
    const icon = toggle.querySelector('.icon');
    if (icon) icon.textContent = theme === 'light' ? 'dark_mode' : 'light_mode';
  });
  document.querySelectorAll('meta[name="theme-color"]').forEach((meta) => {
    meta.setAttribute('content', themeColors[theme]);
  });
}

themeToggles.forEach((toggle) => {
  toggle.addEventListener('click', () => {
    root.dataset.theme = activeTheme() === 'light' ? 'dark' : 'light';
    syncThemeControls();
  });
});
prefersLight.addEventListener('change', () => {
  if (!root.dataset.theme) syncThemeControls();
});
syncThemeControls();

const copyButton = document.querySelector('[data-copy-command]');
const copyLabel = document.querySelector('[data-copy-label]');
const command = document.querySelector('[data-command]');
const copyStatus = document.querySelector('#copy-status');

async function copyQuickStart() {
  if (!copyButton || !copyLabel || !command || !copyStatus) return;
  copyButton.disabled = true;
  try {
    await navigator.clipboard.writeText(command.textContent.trim());
    copyLabel.textContent = 'Copied';
    copyStatus.textContent = 'Docker command copied to the clipboard.';
  } catch {
    copyLabel.textContent = 'Copy';
    copyStatus.textContent = 'Copy unavailable. Select the command and copy it manually.';
  } finally {
    copyButton.disabled = false;
  }
}

copyButton?.addEventListener('click', copyQuickStart);
