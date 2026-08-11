/*
 * Copies vendored frontend assets from node_modules into static/vendor/.
 *
 * Usage:  npm run vendor   (after npm ci / npm install)
 *
 * Node is only needed to (re)generate these assets, never at runtime. The
 * committed files under static/vendor/ are what the Flask app actually serves.
 * To update a library: bump its version in package.json, run `npm install`,
 * then `npm run vendor`, and commit the changed static/vendor/ files.
 */
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const nodeModules = path.join(root, 'node_modules');
const outDir = path.join(root, 'static', 'vendor');
const checkOnly = process.argv.includes('--check');

// [ source (relative to node_modules), destination (relative to static/vendor) ]
const files = [
  ['@xterm/xterm/css/xterm.css', 'xterm/xterm.css'],
  ['@xterm/xterm/lib/xterm.js', 'xterm/xterm.js'],
  ['@xterm/addon-fit/lib/addon-fit.js', 'xterm/xterm-addon-fit.js'],
  ['@xterm/addon-search/lib/addon-search.js', 'xterm/xterm-addon-search.js'],
  ['@highlightjs/cdn-assets/highlight.min.js', 'highlight/highlight.min.js'],
  ['@highlightjs/cdn-assets/styles/github-dark.min.css', 'highlight/github-dark.min.css'],
  ['socket.io-client/dist/socket.io.min.js', 'socketio/socket.io.min.js'],
  // Material Icons: only the "filled" variant is used by the UI. The CSS
  // references its fonts relatively, so CSS + woff2 + woff land side by side.
  ['material-icons/iconfont/material-icons.css', 'material-icons/material-icons.css'],
  ['material-icons/iconfont/material-icons.woff2', 'material-icons/material-icons.woff2'],
  ['material-icons/iconfont/material-icons.woff', 'material-icons/material-icons.woff'],
];

function expectedContents(srcPath, dest) {
  const source = fs.readFileSync(srcPath);
  if (dest !== 'socketio/socket.io.min.js') return source;

  const vulnerableDecoder = 'if(o!=Number(o)||"-"!==t.charAt(i))throw new Error("Illegal attachments");r.attachments=Number(o)';
  const patchedDecoder = 'if(o!=Number(o)||"-"!==t.charAt(i))throw new Error("Illegal attachments");var a=Number(o);if(!Number.isInteger(a)||a<1)throw new Error("Illegal attachments");if(a>10)throw new Error("too many attachments");r.attachments=a';
  const bundle = source.toString('utf8');
  const matches = bundle.split(vulnerableDecoder).length - 1;
  if (matches !== 1) {
    throw new Error('Socket.IO bundle decoder changed; review the CVE-2026-69185 patch.');
  }
  return Buffer.from(bundle.replace(vulnerableDecoder, patchedDecoder), 'utf8');
}

function contentsMatch(srcPath, destPath, dest) {
  const source = expectedContents(srcPath, dest);
  const destination = fs.readFileSync(destPath);
  if (!/\.(?:css|js)$/.test(dest)) return source.equals(destination);
  const normalize = value => value.toString('utf8').replace(/\r\n/g, '\n');
  return normalize(source) === normalize(destination);
}

let count = 0;
const stale = [];
for (const [src, dest] of files) {
  const srcPath = path.join(nodeModules, src);
  const destPath = path.join(outDir, dest);
  if (!fs.existsSync(srcPath)) {
    console.error(`ERROR: missing source file: ${src}\nRun "npm install" first.`);
    process.exit(1);
  }
  if (checkOnly) {
    if (!fs.existsSync(destPath)
        || !contentsMatch(srcPath, destPath, dest)) {
      stale.push(dest);
    }
  } else {
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.writeFileSync(destPath, expectedContents(srcPath, dest));
    console.log(`  ${src}  ->  static/vendor/${dest}`);
  }
  count++;
}
if (checkOnly) {
  if (stale.length) {
    console.error(
      `ERROR: stale vendored assets: ${stale.join(', ')}\n`
      + 'Run "npm run vendor" and commit the resulting files.'
    );
    process.exit(1);
  }
  console.log(`Verified ${count} vendored frontend assets.`);
} else {
  console.log(`\nVendored ${count} files into static/vendor/.`);
}
