package audit

import (
	"errors"
	"syscall"
)

// openNoFollow is added to every open of a log file: a link in its place
// is refused, not followed, and a FIFO does not block the open. Files of
// the log are checked as regular after the open.
const openNoFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// isLink reports the error of an O_NOFOLLOW open of a link.
func isLink(err error) bool { return errors.Is(err, syscall.ELOOP) }
