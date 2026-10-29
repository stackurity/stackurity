package store

// SetAfterPriorityChunk installs a function run after each committed chunk
// of a prioritisation pass, and returns a function that removes it.
func SetAfterPriorityChunk(f func(written int) error) func() {
	afterPriorityChunk = f
	return func() { afterPriorityChunk = nil }
}
