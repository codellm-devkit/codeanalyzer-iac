//go:build !unix

package filesystem

import "os"

const safeOpenFlags = os.O_RDONLY
