'use strict';

// Invoked before opening a link, while the preceding active link is still a root.
// Scan both buffers only after the table has grown substantially. Marker lines
// alone are insufficient: wrapping/reflow can place a cell on another line.
function pruneUnusedLinks(activeId) {
  if (this._dataByLinkId.size < (this._linkPruneThreshold || 1024)) return;
  const roots = new Set([activeId]);
  for (const buffer of [this._bufferService.buffers.normal, this._bufferService.buffers.alt]) {
    roots.add(buffer.savedCurAttrData?.extended?.urlId);
    for (let row = 0; row < buffer.lines.length; row++) {
      const line = buffer.lines.get(row);
      for (let col = 0; col < line.length; col++) {
        // Stale extended-attribute slots are not live unless the cell flag is set.
        if (line.getBg(col) & 268435456) roots.add(line._extendedAttrs[col]?.urlId);
      }
    }
  }
  for (const entry of Array.from(this._dataByLinkId.values())) {
    if (roots.has(entry.id)) continue;
    for (const marker of entry.lines.slice()) {
      marker.dispose();
    }
  }
  this._linkPruneThreshold = Math.max(1024, this._dataByLinkId.size * 2);
}

function hardenXtermLinks(bundle) {
  const insertion = 'registerLink(e){const t=this._bufferService.buffer;';
  const opening = '_createHyperlink(e,t){this._getCurrentLinkId()&&';
  const guardedOpening = '_createHyperlink(e,t){this._oscLinkService.pruneUnusedLinks(this._getCurrentLinkId());this._getCurrentLinkId()&&';
  const method = pruneUnusedLinks.toString().replace(/^function /, '');
  if (bundle.includes(guardedOpening) && bundle.includes(method)) return bundle;
  for (const anchor of [insertion, opening]) {
    if (bundle.split(anchor).length !== 2) {
      throw new Error('xterm link lifecycle changed; review the unused-link pruning patch.');
    }
  }
  return bundle.replace(insertion, method + insertion).replace(opening, guardedOpening);
}

module.exports = {hardenXtermLinks};
