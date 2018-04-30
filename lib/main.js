const { satisfies } = require('./versions');
const normalize = require('./normalize');

const datasets = {
  'node-swg': require('./sources/node-swg'),
  'retire.js': require('./sources/retirejs'),
  'jergal/unnecessary': require('../lists/unnecessary'),
};

// Order is important
const defaultSources = [
  'node-swg',
  'retire.js',
  'jergal/unnecessary',
];

class Jergal {
  constructor(opts = {}) {
    this.entries = new Map();
    this.known = new Set();

    for (const sourceName of opts.sources || defaultSources) {
      if (!datasets.hasOwnProperty(sourceName))
        throw new Error(`No such source: ${sourceName}`);
      const source = datasets[sourceName];
      if (source.init && !source.initialized)
        throw new Error(
          `Source ${sourceName} is not initialized. ` +
          'Call `await Jergal.init(opts)` first, or create instances with ' +
          '`await Jergal.create(opts)` instead.'
        );
      for (const [name, list] of source.entries) {
        for (const entry of list) {
          if (!entry.source) entry.source = sourceName;
          if (!entry.type && sourceName.includes('/'))
            entry.type = sourceName.split('/').pop();
        }
        const entries = list.filter(entry => {
          if (opts.types && !opts.types.includes(entry.type)) return false;
          return true;
        });
        if (entries.length === 0) continue;
        this.known.add(name);
        if (!this.entries.has(name)) this.entries.set(name, []);
        const target = this.entries.get(name);
        for (const entry of entries) {
          target.push(entry);
        }
      }
    }
  }
  static async init(opts = {}) {
    for (const sourceName of opts.sources || defaultSources) {
      if (!datasets.hasOwnProperty(sourceName))
        throw new Error(`No such source: ${sourceName}`);
      const source = datasets[sourceName];
      if (!source.entries || !(source.entries instanceof Map)) {
        for (const list of Object.values(source)) {
          for (const entry of list) {
            normalize.auto(entry);
          }
        }
        const entries = new Map(Object.entries(source));
        datasets[sourceName] = { entries };
        datasets[sourceName].initialized = true;
        continue;
      }
      if (source.initialized) continue;
      if (source.init) await source.init();
      source.initialized = true;
    }
  }
  static async create(opts = {}) {
    await Jergal.init(opts);
    return new Jergal(opts);
  }
  check(name, version) {
    const have = new Set();
    const result = [];
    for (const entry of this.entries.get(name) || []) {
      const { patched_versions, affected_versions } = entry;
      if (patched_versions && satisfies(version, patched_versions))
        continue;
      if (affected_versions && !satisfies(version, affected_versions))
        continue;
      const tokens = new Set([entry.id, ...entry.references, ...entry.cves]);
      if ([...tokens].some(token => token && have.has(token))) continue;
      for (const token of tokens) have.add(token);
      result.push(Object.assign({ name, version }, entry));
    }
    return result;
  }
}

Jergal.Jergal = Jergal;

module.exports = Jergal;
