'use strict';

const fs = require('fs');
const path = require('path');
const semver = require('semver');

// This should have been exported by `swg-vulnerabilities`, really...
const location = ['.', '../..', '../../../..']
  .map(sep => path.join(
    __dirname, '..', sep,
    'node_modules/swg-vulnerabilities/security-wg-master/vuln/npm/'
  ))
  .find(loc => fs.existsSync(loc));

if (!location) throw new Error('Could not find vuln/npm dir!');

const entries = new Map();
const known = new Set();

for (const file of fs.readdirSync(location)) {
  if (!file.endsWith('.json')) continue;
  const json = JSON.parse(fs.readFileSync(path.join(location, file), 'utf-8'));
  const { module_name } = json;
  if (!module_name) throw new Error('No module name!');
  known.add(module_name);
  if (!entries.has(module_name)) entries.set(module_name, []);
  entries.get(module_name).push(json);
}

// TODO: inspect entries without proper .vulnerable_versions field

function check(name, version) {
  return (entries.get(name) || []).map(entry => {
    const { vulnerable_versions, patched_versions } = entry;
    if (patched_versions && semver.satisfies(version, patched_versions))
      return null;
    if (vulnerable_versions && !semver.satisfies(version, vulnerable_versions))
      return null;
    return {
      type: 'vulnerability',
      cvss_vector: entry.cvss_vector,
      cvss_score: entry.cvss_score,
      title: entry.title,
      publish_date: entry.publish_date
        ? new Date(entry.publish_date)
        : undefined,
      recommendation: entry.recommendation,
      raw: entry
    };
  }).filter(x => x);
}

module.exports = {
  entries,
  known,
  check
};
