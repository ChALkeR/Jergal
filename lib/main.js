const swg = require('./node-swg');

const known = new Set([
  ...swg.known
]);

function check(name, version) {
  return [
    ...swg.check(name, version),
  ];
}

module.exports = { check, known };
