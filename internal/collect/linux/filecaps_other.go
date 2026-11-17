//go:build !unix

package linux

func fileCaps(string) bool { return false }
