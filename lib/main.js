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

function satisfies(version, range) {
  // Range '<=99.999.99999' means "all versions", but fails on "2014.10.20-1"
  if (range === '<=99.999.99999') return true;
  if (semver.satisfies(version, range)) return true;
  if (range.startsWith('>=')) {
    const sub = range.slice(2).trim();
    if (semver.valid(sub) && semver.gte(version, sub)) return true;
  } else if (range.startsWith('<=')) {
    const sub = range.slice(2).trim();
    if (semver.valid(sub) && semver.lte(version, sub)) return true;
  } else if (range.startsWith('>')) {
    const sub = range.slice(1).trim();
    if (semver.valid(sub) && semver.gt(version, sub)) return true;
  } else if (range.startsWith('<')) {
    const sub = range.slice(1).trim();
    if (semver.valid(sub) && semver.lt(version, sub)) return true;
  }
  return false;
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
  }
  return result;
}

module.exports = {
  init,
  check,
  known,
};
