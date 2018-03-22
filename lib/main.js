const swg = require('./node-swg');

const known = new Set([
  ...swg.known
]);

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

module.exports = { check, known };
