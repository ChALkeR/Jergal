const { satisfies } = require('./versions');

const swg = require('./sources/node-swg');
const retirejs = require('./sources/retirejs');

const known = new Set();
const entries = new Map();

async function init() {
  const sources = [swg, retirejs];
  for (const source of sources) {
    await source.init();
    for (const [name, list] of source.entries) {
      known.add(name);
      if (!entries.has(name)) entries.set(name, []);
      const target = entries.get(name);
      for (const entry of list) target.push(entry);
    }
  }
}

function check(name, version) {
  const have = new Set();
  const result = [];
  for (const entry of entries.get(name) || []) {
    const { patched_versions, affected_versions } = entry;
    if (patched_versions && satisfies(version, patched_versions))
      continue;
    if (affected_versions && !satisfies(version, affected_versions))
      continue;
    const tokens = new Set([entry.id, ...entry.references, ...entry.cves]);
    if ([...tokens].some(token => token && have.has(token))) continue;
    for (const token of tokens) have.add(token);
    result.push(Object.assign({ name, version }, entry));
    if (entry.id && entry.id.startsWith('NSWG-ECO-') && entry.source !== 'security-wg')
      console.error('WTF', name, version, entry.id, entry.source)
  }
  return result;
}

module.exports = {
  init,
  check,
  known,
};
