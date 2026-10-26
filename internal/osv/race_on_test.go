//go:build race

package osv

// The race detector slows comparisons by roughly 5 to 10 times.
const timeBudgetFactor = 10
