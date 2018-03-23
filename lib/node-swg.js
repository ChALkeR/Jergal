'use strict';

const fs = require('fs');
const util = require('util');
const path = require('path');
const location = require('swg-vulnerabilities').npmPath;

const entries = new Map();

const readdir = util.promisify(fs.readdir);
const readFile = util.promisify(fs.readFile);

async function init() {
  for (const file of await readdir(location)) {
    if (!file.endsWith('.json')) continue;
    const json = JSON.parse(await readFile(path.join(location, file), 'utf-8'));
    const { module_name } = json;
    if (!module_name) throw new Error('No module name!');
    if (!entries.has(module_name)) entries.set(module_name, []);
    entries.get(module_name).push(preprocess(json));
  }
}

// TODO: inspect entries without proper .vulnerable_versions field

function preprocess(raw) {
  const references = [];
  if (raw.references) {
    for (const ref of raw.references.trim().split('\n')) {
      references.push(ref.trim().replace(/^\s*[\*\-]+\s*/, ''));
    }
  }
  return {
    type: 'vulnerability',
    id: `NSWG-ECO-${raw.id}`,
    source: 'security-wg',
    cves: raw.cves || [],
    affected_versions: raw.vulnerable_versions,
    patched_versions: raw.patched_versions,
    cvss_vector: raw.cvss_vector,
    cvss_score: raw.cvss_score,
    title: raw.title,
    publish_date: raw.publish_date
      ? new Date(raw.publish_date)
      : undefined,
    recommendation: raw.recommendation,
    description: raw.overview,
    references,
    raw
  };
}

module.exports = {
  init,
  entries,
};
