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
const {hardenXtermLinks} = require('./xterm-link-hardening');

const root = path.resolve(__dirname, '..');
const nodeModules = path.join(root, 'node_modules');
const outDir = path.join(root, 'static', 'vendor');
const checkOnly = process.argv.includes('--check');

// [ source (relative to node_modules), destination (relative to static/vendor) ]
const files = [
  ['@xterm/xterm/LICENSE', 'xterm/LICENSE'],
  ['@xterm/addon-fit/LICENSE', 'xterm/LICENSE-addon-fit'],
  ['@xterm/addon-search/LICENSE', 'xterm/LICENSE-addon-search'],
  ['@highlightjs/cdn-assets/LICENSE', 'highlight/LICENSE'],
  ['socket.io-client/LICENSE', 'socketio/LICENSE'],
  ['material-icons/LICENSE', 'material-icons/LICENSE'],
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
  if (dest === 'socketio/socket.io.min.js') {
    // A polling XHR with status 0 has already lost its network channel. Sending
    // another close POST during error cleanup can start a request from a departing
    // document. Close locally while preserving the original error and reconnect
    // path. Normal shutdown and HTTP error responses retain upstream behavior.
    const prefix = 'i.V=function(t,n){if("opening"===this.readyState||"open"===this.readyState||"closing"===this.readyState){if(this.clearTimeoutFn(this.Z),';
    const before = prefix + 'this.transport.removeAllListeners("close"),this.transport.close(),this.transport.removeAllListeners()';
    const after = prefix + 'this.transport.removeAllListeners("close"),("transport error"===t&&"polling"===this.transport.name&&n&&0===n.description?this.transport.onClose():this.transport.close()),this.transport.removeAllListeners()';
    const bundle = source.toString('utf8');
    if (bundle.split(before).length !== 2) {
      throw new Error('Socket.IO error cleanup changed; review the failed-polling close patch.');
    }
    return Buffer.from(bundle.replace(before, after), 'utf8');
  }
  if (dest === 'xterm/xterm.js') {
    const parserLimit = 't.PAYLOAD_LIMIT=1e7';
    const boundedParserLimit = 't.PAYLOAD_LIMIT=2e5';
    const bundle = source.toString('utf8');
    const matches = bundle.split(parserLimit).length - 1;
    if (matches !== 1) {
      throw new Error(
        'xterm parser limit changed; review the OSC/DCS memory-bound patch.'
      );
    }
    let patched = bundle.replace(parserLimit, boundedParserLimit);
    // CSI counts are remotely controlled. Saturating operations need at most
    // one screen of work; REP also needs a bound on expanded payload size.
    const replacements = [
      ['parse(e,t){let i,s=this._activeBuffer.x,r=this._activeBuffer.y,n=0;const o=this._parseStack.paused;',
        'parse(e,t){let i,s=this._activeBuffer.x,r=this._activeBuffer.y,n=0;const o=this._parseStack.paused;if(!o)this._websshRepeatBudget=2e5;'],
      ['let t=e.params[0]||1;for(;t--;)this._activeBuffer.x=this._activeBuffer.nextStop()', 'let t=Math.min(e.params[0]||1,this._bufferService.cols);for(;t--;)this._activeBuffer.x=this._activeBuffer.nextStop()'],
      ['let t=e.params[0]||1;for(;t--;)this._activeBuffer.x=this._activeBuffer.prevStop()', 'let t=Math.min(e.params[0]||1,this._bufferService.cols);for(;t--;)this._activeBuffer.x=this._activeBuffer.prevStop()'],
      ...['insertLines', 'deleteLines'].map(method => [
        `${method}(e){this._restrictCursor();let t=e.params[0]||1;`,
        `${method}(e){this._restrictCursor();let t=Math.min(e.params[0]||1,this._activeBuffer.scrollBottom-this._activeBuffer.y+1);`,
      ]),
      ...['scrollUp', 'scrollDown'].map(method => [
        `${method}(e){let t=e.params[0]||1;`,
        `${method}(e){let t=Math.min(e.params[0]||1,this._activeBuffer.scrollBottom-this._activeBuffer.scrollTop+1);`,
      ]),
      ['const i=e.params[0]||1,s=p.UnicodeService.extractWidth(t),r=this._activeBuffer.x-s,n=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y).getString(r),o=new Uint32Array(n.length*i);',
        'const s=p.UnicodeService.extractWidth(t),r=this._activeBuffer.x-s,n=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y).getString(r);const i=Math.min(e.params[0]||1,Math.floor(this._websshRepeatBudget/Math.max(1,n.length)));if(!i)return!0;this._websshRepeatBudget-=n.length*i;const o=new Uint32Array(n.length*i);'],
    ];
    for (const [before, after] of replacements) {
      if (patched.split(before).length !== 2) {
        throw new Error('xterm CSI implementation changed; review the bounded-count patch.');
      }
      patched = patched.replace(before, after);
    }
    return Buffer.from(hardenXtermLinks(patched), 'utf8');
  }
  return source;
}

function contentsMatch(srcPath, destPath, dest) {
  const source = expectedContents(srcPath, dest);
  const destination = fs.readFileSync(destPath);
  if (!/\.(?:css|js)$/.test(dest) && !/(?:^|\/)LICENSE(?:-|$)/.test(dest)) {
    return source.equals(destination);
  }
  const normalize = value => value.toString('utf8').replace(/\r\n/g, '\n');
  return normalize(source) === normalize(destination);
}

// Fonts are built separately from pinned upstream release archives. Verify
// their committed bytes in the normal vendor check as well (no network).
const crypto = require('node:crypto');
const fontDir = path.join(outDir, 'terminal-fonts');
const fontManifest = JSON.parse(fs.readFileSync(path.join(fontDir, 'manifest.json'), 'utf8'));
for (const font of fontManifest.fonts) {
  for (const asset of font.files) {
    const bytes = fs.readFileSync(path.join(fontDir, asset.file));
    if (bytes.subarray(0, 4).toString() !== 'wOF2'
        || crypto.createHash('sha256').update(bytes).digest('hex') !== asset.sha256) {
      throw new Error(`Terminal font integrity mismatch: ${asset.file}`);
    }
  }
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
