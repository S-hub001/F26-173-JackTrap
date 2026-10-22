// SAFE SIMULATION: this file does nothing. It only contains miner-like words.
var settings = {
  lib: "CoinHive",
  algo: "CryptoNight",
  pool: "stratum+tcp://example.invalid:4444",
  hashrate: 0
};
function startFake() { var miner = { start: function () {} }; miner.start(); }
