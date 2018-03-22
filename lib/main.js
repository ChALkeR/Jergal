const semver = require('semver');

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
      if (patched_versions && semver.satisfies(version, patched_versions))
        continue;
      if (affected_versions && !semver.satisfies(version, affected_versions))
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

    entry.name = name;
    entry.version = version;
    result.push(entry);
  }
  return result;
}

module.exports = {
  init,
  check,
  known,
};
