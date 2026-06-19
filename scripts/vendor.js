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

// [ source (relative to node_modules), destination (relative to static/vendor) ]
const files = [
  ['xterm/css/xterm.css', 'xterm/xterm.css'],
  ['xterm/lib/xterm.js', 'xterm/xterm.js'],
  ['xterm-addon-fit/lib/xterm-addon-fit.js', 'xterm/xterm-addon-fit.js'],
  ['xterm-addon-search/lib/xterm-addon-search.js', 'xterm/xterm-addon-search.js'],
  ['@highlightjs/cdn-assets/highlight.min.js', 'highlight/highlight.min.js'],
  ['@highlightjs/cdn-assets/styles/github-dark.min.css', 'highlight/github-dark.min.css'],
  ['socket.io-client/dist/socket.io.min.js', 'socketio/socket.io.min.js'],
  // Material Icons: only the "filled" variant is used by the UI. The CSS
  // references its fonts relatively, so CSS + woff2 + woff land side by side.
  ['material-icons/iconfont/material-icons.css', 'material-icons/material-icons.css'],
  ['material-icons/iconfont/material-icons.woff2', 'material-icons/material-icons.woff2'],
  ['material-icons/iconfont/material-icons.woff', 'material-icons/material-icons.woff'],
];

let count = 0;
for (const [src, dest] of files) {
  const srcPath = path.join(nodeModules, src);
  const destPath = path.join(outDir, dest);
  if (!fs.existsSync(srcPath)) {
    console.error(`ERROR: missing source file: ${src}\nRun "npm install" first.`);
    process.exit(1);
  }
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.copyFileSync(srcPath, destPath);
  console.log(`  ${src}  ->  static/vendor/${dest}`);
  count++;
}
console.log(`\nVendored ${count} files into static/vendor/.`);
