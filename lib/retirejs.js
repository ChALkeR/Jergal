'use strict';

const fetch = require('node-fetch');
const normalize = require('./normalize');
const repo = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/npmrepository.json';

const entries = new Map();

async function init() {
  const res = await fetch(repo);
  const data = await res.json();
  for (const name of Object.keys(data)) {
    entries.set(name, data[name].vulnerabilities.map(preprocess));
  }
}

function preprocess(raw) {
  const entry = {
    type: 'vulnerability',
    source: 'retire.js',
    severity: raw.severity,
    title: raw.identifiers
      ? raw.identifiers.summary || raw.identifiers.advisory
      : undefined,
    references: raw.info || [],
    cves: raw.identifiers && raw.identifiers.CVE || [],
    raw,
  };
  if (raw.below && raw.below !== '100') {
    entry.patched_versions = `>=${normalize.version(raw.below)}`;
  }
  if (raw.atOrAbove) {
    entry.affected_versions = `>=${normalize.version(raw.atOrAbove)}`;
  }
  return normalize.auto(entry);
}

module.exports = {
  init,
  entries,
};

