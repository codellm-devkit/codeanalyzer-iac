//go:build unix

package filesystem

import (
	"os"
	"syscall"
)

// safeOpenFlags makes an accidental FIFO replacement non-blocking until its
// opened descriptor can be verified as regular.
const safeOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK
