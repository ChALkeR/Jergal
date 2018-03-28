'use strict';

const fetch = require('node-fetch');
const normalize = require('../normalize');
const repo = `https://raw.githubusercontent.com/nodejs/security-wg/master/vuln/npm/`;

const entries = new Map();

async function init() {
  const bs = 50;
  for (let start = 1; ; start += bs) {
    const ids = Array(bs).fill(0).map((x, i) => start + i);
    const ress = await Promise.all(ids.map(id => fetch(`${repo}${id}.json`)));
    if (ress.some(res => res.status !== 200 && res.status !== 404)) {
      throw new Error('Fetch failed!');
    }
    if (ress.every(res => res.status === 404)) break;
    const jsons = await Promise.all(
      ress.filter(res => res.status === 200).map(res => res.json())
    );
    for (const json of jsons) {
      const { module_name } = json;
      if (!module_name) throw new Error('No module name!');
      if (!entries.has(module_name)) entries.set(module_name, []);
      entries.get(module_name).push(preprocess(json));
    }
  }
}

// TODO: inspect entries without proper .vulnerable_versions field

function preprocess(raw) {
  const entry = {
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
    references: (raw.references || '').split('\n'),
    raw
  };
  if (raw.slug && raw.coordinating_vendor === '^Lift Security') {
    // There are duplicate slugs that break deduping.  Also, nodesecurity gives
    // a 500 error for those, so let's not use them
    // entry.references.push(`https://nodesecurity.io/advisories/${raw.slug}`);
  }
  return normalize.auto(entry);
}

module.exports = {
  init,
  entries,
};
