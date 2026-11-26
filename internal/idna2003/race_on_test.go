//go:build race

package idna2003

// raceEnabled skips the exhaustive comparisons under the race detector:
// the functions are pure, and the run would take twenty times as long.
const raceEnabled = true
