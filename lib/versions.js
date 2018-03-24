const semver = require('semver');

// A more loose check that semver, using a simple order check
function satisfies(version, range) {
  range = range.trim();

  // Range '<=99.999.99999' means "all versions", but fails on "2014.10.20-1"
  if (range === '<=99.999.99999') return true;

  // If semver satisfies, we return true
  if (semver.satisfies(version, range)) return true;

  if (range.includes('||')) {
    // Multiple ranges, "or"
    return range.split('||').some(sub => satisfies(version, sub.trim()));
  }

  if (range.includes(' ')) {
    // Multiple ranges, "and"
    return range.split(' ')
      .map(x => x.trim())
      .filter(x => x)
      .every(sub => satisfies(version, sub));
  }

  // Comparison
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

module.exports = {
  satisfies,
};
