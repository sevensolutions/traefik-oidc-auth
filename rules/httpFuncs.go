package rules

import (
	"fmt"
	"net/http"
	"regexp"
)

var httpFuncs = map[string]func(*matchersTree, ...string) error{
	"Header":       headerFunc,
	"HeaderRegexp": headerRegexpFunc,
}

func headerFunc(tree *matchersTree, values ...string) error {
	if len(values) != 2 {
		return fmt.Errorf("Header-rule requires exactly two arguments.")
	}

	headerName := values[0]
	headerValue := values[1]

	tree.matcher = func(req *http.Request) bool {
		h := req.Header.Get(headerName)

		return h == headerValue
	}

	return nil
}

func headerRegexpFunc(tree *matchersTree, values ...string) error {
	if len(values) != 2 {
		return fmt.Errorf("HeaderRegexp-rule requires exactly two arguments.")
	}

	headerName := values[0]
	headerValueRegex := values[1]

	headerRegex, err := regexp.Compile(headerValueRegex)
	if err != nil {
		return err
	}

	tree.matcher = func(req *http.Request) bool {
		h := req.Header.Get(headerName)

		return headerRegex.MatchString(h)
	}

	return nil
}
