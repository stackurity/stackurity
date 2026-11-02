//go:build !unix

package docker

const noFollow = 0

func freeBytes(string) (int64, bool) { return 0, false }
