const { satisfies } = require('./versions');

const swg = require('./node-swg');
const retirejs = require('./retirejs');

const known = new Set();

async function init() {
  await swg.init();
  await retirejs.init();

  for (const [name] of [
    ...swg.entries,
    ...retirejs.entries,
  ]) {
    known.add(name);
  }
}

function check(name, version) {
  const entries = [];
  for (const lib of [swg, retirejs]) {
    for (const entry of lib.entries.get(name) || []) {
      const { patched_versions, affected_versions } = entry;
      if (patched_versions && satisfies(version, patched_versions))
        continue;
      if (affected_versions && !satisfies(version, affected_versions))
        continue;
      entries.push(entry);
    }
  }
  const have = new Set();
  const result = [];
  for (const entry of entries) {
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
