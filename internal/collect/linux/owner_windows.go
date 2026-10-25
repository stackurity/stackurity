package linux

import "os"

// The Linux collector does not run on Windows; these keep the package
// building there.
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }

func currentUID() uint32 { return 0 }
