package store

import (
	"errors"
	"fmt"
)

// ErrNotFound is matched (errors.Is) by the errors GetUser and ResolveMapping
// return when the user or the mapping does not exist, in every backend. Any
// other error from them is a real store failure, not an absence.
var ErrNotFound = errors.New("not found")

// notFoundError keeps the backends' existing messages ("user not found: <guid>")
// while matching ErrNotFound.
type notFoundError struct{ msg string }

func (e *notFoundError) Error() string        { return e.msg }
func (e *notFoundError) Is(target error) bool { return target == ErrNotFound }

func notFound(format string, args ...interface{}) error {
	return &notFoundError{msg: fmt.Sprintf(format, args...)}
}
