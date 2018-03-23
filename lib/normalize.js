'use strict';

const semver = require('semver');

function reference(ref) {
  return ref.trim()
    .replace(/^\s*[\*\-]+\s*/, '')
    .replace('//github.com/chjj/marked/', '//github.com/markedjs/marked/')
    .replace('http://nodesecurity.io/', 'https://nodesecurity.io/');
}

function references(refs) {
  return refs.map(reference).filter(x => x);
}

// Missing entries in https://github.com/nodejs/security-wg/pull/26
const nspMissing = [
  6, 58, 69, 70, 71, 72, 73, 78, 79, 82, 83, 84, 103, 105, 110, 111, 119, 141,
  142, 146, 191, 249, 291, 306, 316, 317, 320, 322, 333, 337,
];

function id(entry) {
  if (entry.id) return entry.id;
  const nodeseclink = /^https?:\/\/nodesecurity.io\/advisories\//;
  const nodesec = entry.references.find(ref => nodeseclink.test(ref));
  if (nodesec) {
    const id = nodesec.replace(nodeseclink, '');
    if (/^[0-9]+$/.test(id)) {
      const int = parseInt(id, 10);
      if (int <= 338 && !nspMissing.includes(int)) {
        // https://github.com/nodejs/security-wg/pull/26
        return `NSWG-ECO-${id}`;
      }
      return `NSP-${id}`;
    }
  }
  if (entry.cves.length === 1) {
    entry.id = entry.cves[0];
  }
  return null;
}

function version(ver) {
  if (!ver) return null;
  ver = ver.trim();
  if (semver.valid(ver)) return ver;
  ver = ver.replace(/\.(alpha|beta)/, '-$1');
  if (semver.valid(ver)) return ver;
  if (ver.split('.').length === 2) ver += '.0';
  if (semver.valid(ver)) return ver;
  if (ver.endsWith('-*')) ver = ver.slice(0, -2);
  if (semver.valid(ver)) return ver;
  ver = ver.replace(/^([0-9]+\.[0-9]+\.[0-9]+)(\.[^-]+)(-.*)?$/, '$1$3');
  if (semver.valid(ver)) return ver;
  ver = ver.replace(/^([0-9]+\.[0-9]+\.[0-9]+)[^0-9].*?$/, '$1');
  if (semver.valid(ver)) return ver;
  console.error(`Could not parse version: ${ver}`);
  return ver;
}

function versionRange(range) {
  if (!range) return null;
  range = range.trim();
  const valid = semver.validRange(range);
  if (valid) return valid;
  console.error(`Could not parse version range: ${range}`);
  return range;
}

function auto(entry) {
  entry.references = references(entry.references || []);
  entry.id = id(entry);
  entry.patched_versions = versionRange(entry.patched_versions);
  entry.affected_versions = versionRange(entry.affected_versions);
  return entry;
}

module.exports = {
  reference,
  references,
  id,
  version,
  versionRange,
  auto,
};
