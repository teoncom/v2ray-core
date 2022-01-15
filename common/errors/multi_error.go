package errors

import (
	"strings"
)

type MultiError []error

func (e MultiError) Error() string {
	if len(e) == 1 {
		return e[0].Error()
	}
	var r strings.Builder
	r.WriteString("multierr: ")
	for _, err := range e {
		r.WriteString(err.Error())
		r.WriteString(" | ")
	}
	return r.String()
}

func Combine(maybeError ...error) error {
	var errs MultiError
	for _, err := range maybeError {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}
