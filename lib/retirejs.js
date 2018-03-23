'use strict';

const fetch = require('node-fetch');
const repo = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/npmrepository.json';

const entries = new Map();

async function init() {
  const res = await fetch(repo);
  const data = await res.json();
  for (const name of Object.keys(data)) {
    entries.set(name, data[name].vulnerabilities.map(preprocess));
  }
}

function fixVersion(version) {
  return version.replace(/\.(alpha|beta)/, '-$1');
}

function getId(entry) {
  if (entry.id) return entry.id;
  const nodeseclink = /^https?:\/\/nodesecurity.io\/advisories\//;
  const nodesec = entry.references.find(ref => nodeseclink.test(ref));
  if (nodesec) {
    const id = nodesec.replace(nodeseclink, '');
    if (/^[0-9]+$/.test(id)) return `NSWG-ECO-${id}`;
  }
  if (entry.cves.length === 1) {
    entry.id = entry.cves[0];
  }
  return undefined;
}

function preprocess(raw) {
  const entry = {
    type: 'vulnerability',
    source: 'retire.js',
    severity: raw.severity,
    title: raw.identifiers ? raw.identifiers.summary : undefined,
    references: raw.info || [],
    cves: raw.identifiers && raw.identifiers.CVE || [],
    raw,
  };
  if (raw.below && raw.below !== '99.999.99999') {
    entry.patched_versions = `>=${fixVersion(raw.below)}`;
  }
  if (raw.atOrAbove) {
    entry.affected_versions = `>=${fixVersion(raw.atOrAbove)}`;
  }
  entry.id = getId(entry);
  return entry;
}

module.exports = {
  init,
  entries,
};

