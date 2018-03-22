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
