package rules

import (
	"fmt"
	"net/http"

	"github.com/sevensolutions/traefik-oidc-auth/logging"
)

type RequestCondition struct {
	Match func(logger *logging.Logger, request *http.Request) bool
}

func ParseRequestCondition(rule string) (*RequestCondition, error) {
	var matcherNames []string
	for matcher := range httpFuncs {
		matcherNames = append(matcherNames, matcher)
	}

	parser, err := NewParser(matcherNames)
	if err != nil {
		return nil, err
	}

	parse, err := parser.Parse(rule)

	buildTree, ok := parse.(TreeBuilder)
	if !ok {
		return nil, fmt.Errorf("error while parsing rule %s", rule)
	}

	tree := buildTree()

	var matchers requestConditionTree
	err = matchers.addRule(tree, httpFuncs)
	if err != nil {
		return nil, fmt.Errorf("error while adding rule %s: %w", rule, err)
	}

	return &RequestCondition{
		Match: func(logger *logging.Logger, request *http.Request) bool {
			return matchers.match(logger, request)
		},
	}, nil
}

type requestConditionTree struct {
	// matcher is a matcher func used to match HTTP request properties.
	// If matcher is not nil, it means that this matcherTree is a leaf of the tree.
	// It is therefore mutually exclusive with left and right.
	matcher func(logger *logging.Logger, request *http.Request) bool

	// operator to combine the evaluation of left and right leaves.
	operator string
	// Mutually exclusive with matcher.
	left  *requestConditionTree
	right *requestConditionTree
}

func (m *requestConditionTree) match(logger *logging.Logger, request *http.Request) bool {
	if m == nil {
		// This should never happen as it should have been detected during parsing.
		logger.Log(logging.LevelWarn, "Rule matcher is nil")
		return false
	}

	if m.matcher != nil {
		return m.matcher(logger, request)
	}

	switch m.operator {
	case "or":
		return m.left.match(logger, request) || m.right.match(logger, request)
	case "and":
		return m.left.match(logger, request) && m.right.match(logger, request)
	default:
		// This should never happen as it should have been detected during parsing.
		logger.Log(logging.LevelWarn, "Invalid rule operator %s", m.operator)
		return false
	}
}

type matcherFuncs map[string]func(*requestConditionTree, ...string) error

func (m *requestConditionTree) addRule(rule *Tree, funcs matcherFuncs) error {
	switch rule.Matcher {
	case "and", "or":
		m.operator = rule.Matcher
		m.left = &requestConditionTree{}
		err := m.left.addRule(rule.RuleLeft, funcs)
		if err != nil {
			return fmt.Errorf("error while adding rule %s: %w", rule.Matcher, err)
		}

		m.right = &requestConditionTree{}
		return m.right.addRule(rule.RuleRight, funcs)
	default:
		err := CheckRule(rule)
		if err != nil {
			return fmt.Errorf("error while checking rule %s: %w", rule.Matcher, err)
		}

		err = funcs[rule.Matcher](m, rule.Value...)
		if err != nil {
			return fmt.Errorf("error while adding rule %s: %w", rule.Matcher, err)
		}

		if rule.Not {
			matcherFunc := m.matcher
			m.matcher = func(logger *logging.Logger, request *http.Request) bool {
				return !matcherFunc(logger, request)
			}
		}
	}

	return nil
}
