package rules

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/sevensolutions/traefik-oidc-auth/logging"
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

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		h := request.Header.Get(headerName)

		matched := h == headerValue

		logger.Log(logging.LevelDebug, "%s Eval rule Header(`%s`, `%s`). Actual value: %s %s", getMatchedText(matched), headerName, headerValue, h)

		return matched
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

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		h := request.Header.Get(headerName)

		matched := headerRegex.MatchString(h)

		logger.Log(logging.LevelDebug, "%s Eval rule HeaderRegexp(`%s`, `%s`). Actual value: %s", getMatchedText(matched), headerName, headerValueRegex, h)

		return matched
	}

	return nil
}

func getMatchedText(matched bool) string {
	if matched {
		return "✅"
	} else {
		return "❌"
	}
}
