const DEFAULT_MAX = 1000;

export class LRUCache {
  constructor(max = DEFAULT_MAX) {
    this.max = max;
    this.map = new Map();
  }

  get(key) {
    if (!this.map.has(key)) {
      return undefined;
    }
    const val = this.map.get(key);
    this.map.delete(key);
    this.map.set(key, val);
    return val;
  }

  set(key, val) {
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.max) {
      this.map.delete(this.map.keys().next().value);
    }
    this.map.set(key, val);
    return this;
  }

  get size() {
    return this.map.size;
  }

  clear() {
    this.map.clear();
  }
}

export const parseCache = new LRUCache();
export const botCache = new LRUCache();
