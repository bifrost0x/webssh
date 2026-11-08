const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const ASSET_DIRECTORY = path.join(ROOT, 'assets');
const TRANSIENT_CAPTURE_DIRECTORY = path.join(ROOT, '.test-run.tmp', 'captures');

// Only captures consumed by a public repository surface belong in assets/.
const PUBLISHED_CAPTURE_ASSETS = new Set([
    'dashboard.png',
    'dashboard-customize.png',
    'host-discovery.png',
    'commandlibrary.png',
    'command-set-builder.png',
    'file-edit-review.png',
    'mobile-workspace.png',
    'multi-session.png',
    'security-center.png',
    'session-workspace.png',
    'sftp-workspace.png',
    'workspace-overview.png',
]);

// Every published capture shows the same theme, so the README reads as one product.
const CAPTURE_THEME = 'arctic-ice';

/** Switch the page to the capture theme and let its scene and fonts settle. */
async function applyCaptureTheme(page) {
    const changed = await page.evaluate(theme => {
        const changed = document.body.dataset.theme !== theme;
        window.ThemePreference?.store?.(theme);
        document.body.dataset.theme = theme;
        return changed;
    }, CAPTURE_THEME);
    await page.evaluate(() => document.fonts?.ready);
    if (changed) await page.waitForTimeout(700);
}

function captureOutputPath(filename) {
    if (typeof filename !== 'string'
        || path.basename(filename) !== filename
        || !filename.endsWith('.png')) {
        throw new TypeError('Capture filename must be a plain PNG filename');
    }
    const directory = PUBLISHED_CAPTURE_ASSETS.has(filename)
        ? ASSET_DIRECTORY
        : TRANSIENT_CAPTURE_DIRECTORY;
    fs.mkdirSync(directory, { recursive: true });
    return path.join(directory, filename);
}

module.exports = {
    CAPTURE_THEME,
    PUBLISHED_CAPTURE_ASSETS,
    applyCaptureTheme,
    captureOutputPath,
};
