const swg = require('./node-swg');

const known = new Set();

async function init() {
  await swg.init();

  for (const name of [
    ...swg.known,
  ]) {
    known.add(name);
  }
}

function check(name, version) {
  const entries = [
    ...swg.check(name, version),
  ];
  for (const entry of entries) {
    entry.name = name;
    entry.version = version;
  }
  return entries;
}

module.exports = {
  init,
  check,
  known,
};
