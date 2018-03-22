'use strict';

const fs = require('fs');
const path = require('path');
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
  const nodeseclink = 'https://nodesecurity.io/advisories/';
  const nodesec = entry.references.find(ref => ref.startsWith(nodeseclink));
  if (nodesec) {
    entry.id = `NSWG-ECO-${nodesec.slice(nodeseclink.length)}`;
  } else if (entry.cves.length === 1) {
    entry.id = entry.cves[0];
  }
  return entry;
}

module.exports = {
  init,
  entries,
};

