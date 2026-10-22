// Layer 1 signature list.
// weight 4 = strong sign, 2 = possible sign, 1 = weak sign.
// Weak words ("worker", "pool", "wallet") are everywhere in honest code, so
// they only count when a strong or possible sign is also present.
// "core: true" marks the ten words from the supervisor's list.
const SIGNATURES = [
  // Strong: names and strings that almost only miners use
  { keyword: 'coinhive', weight: 4, core: true, note: 'Browser Monero miner library. Shut down in 2019, but copied widely.' },
  { keyword: 'cryptonight', weight: 4, core: true, note: 'The hashing algorithm Monero miners use (made for ordinary CPUs).' },
  { keyword: 'miner.start(', weight: 4, core: true, note: 'The call that switches a JavaScript miner on.' },
  { keyword: 'xmrig', weight: 4, core: true, note: 'Popular open-source Monero miner. It has a WebAssembly build.' },
  { keyword: 'authedmine', weight: 4, note: 'CoinHive\u2019s opt-in version. Clones still use the name.' },
  { keyword: 'cryptoloot', weight: 4, note: 'A CoinHive-style mining service.' },
  { keyword: 'stratum+tcp', weight: 4, note: 'Address format used to reach a mining pool.' },

  // Possible: suspicious, but some honest code uses them
  { keyword: 'webassembly.instantiate', weight: 2, core: true, note: 'Starts a WebAssembly module. Miners use it for speed, but so do games and editors.' },
  { keyword: 'webassembly.instantiatestreaming', weight: 2, note: 'Same as above, but loads the module while it downloads.' },
  { keyword: 'webassembly.compile', weight: 2, note: 'Compiles a WebAssembly module before running it.' },
  { keyword: 'stratum', weight: 2, core: true, note: 'The protocol miners use to talk to a pool.' },
  { keyword: 'hashrate', weight: 2, core: true, note: 'How fast a miner is hashing. Miner dashboards show it.' },

  // Weak: common words, only counted next to a stronger sign
  { keyword: 'worker', weight: 1, core: true, note: 'Background threads. Miners hide in them, but many sites use them.' },
  { keyword: 'wallet', weight: 1, core: true, note: 'Where mined coins are paid out.' },
  { keyword: 'pool', weight: 1, core: true, note: 'The server group a miner works for.' }
];

if (typeof module !== 'undefined') {
  module.exports = SIGNATURES;
}
