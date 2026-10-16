document.documentElement.classList.add('js');

const navToggle = document.querySelector('[data-nav-toggle]');
const navigation = document.querySelector('[data-navigation]');

function closeNavigation() {
  if (!navToggle || !navigation) return;
  navToggle.setAttribute('aria-expanded', 'false');
  navigation.dataset.open = 'false';
}

if (navToggle && navigation) {
  navToggle.addEventListener('click', () => {
    const isOpen = navToggle.getAttribute('aria-expanded') === 'true';
    navToggle.setAttribute('aria-expanded', String(!isOpen));
    navigation.dataset.open = String(!isOpen);
  });
  navigation.addEventListener('click', (event) => {
    if (event.target.closest('a')) closeNavigation();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && navToggle.getAttribute('aria-expanded') === 'true') {
      closeNavigation();
      navToggle.focus();
    }
  });
  window.matchMedia('(min-width: 801px)').addEventListener('change', closeNavigation);
}

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
