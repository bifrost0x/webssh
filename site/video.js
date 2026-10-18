const videoStage = document.querySelector('[data-youtube-player]');
const videoPlaceholder = document.querySelector('[data-youtube-placeholder]');
const loadVideoButton = document.querySelector('[data-load-youtube]');
const removeVideoButton = document.querySelector('[data-remove-youtube]');
const videoStatus = document.querySelector('[data-youtube-status]');

if (videoStage && videoPlaceholder && loadVideoButton && removeVideoButton && videoStatus) {
  loadVideoButton.hidden = false;

  loadVideoButton.addEventListener('click', () => {
    if (videoStage.querySelector('iframe')) return;
    const frame = document.createElement('iframe');
    frame.title = 'WebSSH: Self-Hosted SSH & SFTP in Your Browser';
    frame.width = '1280';
    frame.height = '720';
    frame.allow = 'encrypted-media; fullscreen; picture-in-picture';
    frame.allowFullscreen = true;
    // YouTube requires a referrer; disclose only the site origin, never a page path or query.
    frame.referrerPolicy = 'strict-origin-when-cross-origin';
    frame.src = 'https://www.youtube-nocookie.com/embed/mw_qXUnYYVs?playsinline=1&cc_lang_pref=en&cc_load_policy=1';
    videoPlaceholder.hidden = true;
    videoStage.append(frame);
    removeVideoButton.hidden = false;
    videoStatus.textContent = 'YouTube player enabled. If it cannot play here, use Watch on YouTube.';
    frame.focus();
  });

  removeVideoButton.addEventListener('click', () => {
    videoStage.querySelector('iframe')?.remove();
    videoPlaceholder.hidden = false;
    removeVideoButton.hidden = true;
    videoStatus.textContent = 'YouTube player removed. Load it again only if you want to reconnect.';
    loadVideoButton.focus();
  });
}
