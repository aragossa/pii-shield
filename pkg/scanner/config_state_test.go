package scanner

// Test helpers for the atomically-published config snapshot (activeConfig).
// Tests used to read and mutate the package-global currentConfig directly;
// that global was replaced by an immutable snapshot published via UpdateConfig
// (see configState / cfgState). These helpers give tests the same read/mutate
// convenience without reintroducing the data race.

// activeCfg returns a copy of the currently published scanner config.
func activeCfg() Config { return cfgState().config }

// applyCfg loads the active config, lets fn mutate a copy, and republishes it
// through UpdateConfig so derived state (sensitiveRegex, hmacPool) is rebuilt.
func applyCfg(fn func(*Config)) {
	c := cfgState().config
	fn(&c)
	UpdateConfig(c)
}
