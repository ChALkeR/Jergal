const swg = require('./node-swg');
const retirejs = require('./retirejs');

const known = new Set();

async function init() {
  await swg.init();
  await retirejs.init();

  for (const name of [
    ...swg.known,
    ...retirejs.known,
  ]) {
    known.add(name);
  }
}

function check(name, version) {
  const entries = [
    ...swg.check(name, version),
    ...retirejs.check(name, version),
  ];
  const have = new Set();
  const result = [];
  for (const entry of entries) {
    if (entry.id && have.has(entry.id)) continue;
    have.add(entry.id);
    if (entry.references && entry.references.some(ref => have.has(ref))) continue;
    (entry.references || []).forEach(ref => have.add(ref));

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
