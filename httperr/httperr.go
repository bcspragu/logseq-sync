package httperr

import (
	"fmt"
	"net/http"
)

func Extract(err error) (int, string) {
	httpErr, ok := err.(*Error)
	if !ok {
		return http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)
	}

	msg := httpErr.msg
	if msg == "" {
		msg = http.StatusText(httpErr.statusCode)
	}

	return httpErr.statusCode, msg
}

type Error struct {
	err        error
	statusCode int
	msg        string
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%d] %v", e.statusCode, e.err)
}

func (e *Error) WithMessage(msg string) *Error {
	e.msg = msg
	return e
}

func BadRequest(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, format, args...)
}

func MethodNotAllowed(format string, args ...any) *Error {
	return newError(http.StatusMethodNotAllowed, format, args...)
}

func Internal(format string, args ...any) *Error {
	return newError(http.StatusInternalServerError, format, args...)
}

func Conflict(format string, args ...any) *Error {
	return newError(http.StatusConflict, format, args...)
}

func Unauthorized(format string, args ...any) *Error {
	return newError(http.StatusUnauthorized, format, args...)
}

func Forbidden(format string, args ...any) *Error {
	return newError(http.StatusForbidden, format, args...)
}

func NotFound(format string, args ...any) *Error {
	return newError(http.StatusNotFound, format, args...)
}

func Gone(format string, args ...any) *Error {
	return newError(http.StatusGone, format, args...)
}

func newError(statusCode int, format string, args ...any) *Error {
	return &Error{
		statusCode: statusCode,
		err:        fmt.Errorf(format, args...),
	}
}
