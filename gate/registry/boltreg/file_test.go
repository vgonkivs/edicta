package boltreg_test

import "os"

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }
