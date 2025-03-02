package rules

import (
	"fmt"
	"net/http"
)

type RequestCondition struct {
	Match func(request *http.Request) bool
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

	var matchers matchersTree
	err = matchers.addRule(buildTree(), httpFuncs)
	if err != nil {
		return nil, fmt.Errorf("error while adding rule %s: %w", rule, err)
	}

	return &RequestCondition{
		Match: func(request *http.Request) bool {
			return matchers.match(request)
		},
	}, nil
}

type matchersTree struct {
	// matcher is a matcher func used to match HTTP request properties.
	// If matcher is not nil, it means that this matcherTree is a leaf of the tree.
	// It is therefore mutually exclusive with left and right.
	matcher func(*http.Request) bool
	// operator to combine the evaluation of left and right leaves.
	operator string
	// Mutually exclusive with matcher.
	left  *matchersTree
	right *matchersTree
}

func (m *matchersTree) match(req *http.Request) bool {
	if m == nil {
		// This should never happen as it should have been detected during parsing.
		//log.Warn().Msg("Rule matcher is nil")
		return false
	}

	if m.matcher != nil {
		return m.matcher(req)
	}

	switch m.operator {
	case "or":
		return m.left.match(req) || m.right.match(req)
	case "and":
		return m.left.match(req) && m.right.match(req)
	default:
		// This should never happen as it should have been detected during parsing.
		//log.Warn().Str("operator", m.operator).Msg("Invalid rule operator")
		return false
	}
}

type matcherFuncs map[string]func(*matchersTree, ...string) error

func (m *matchersTree) addRule(rule *Tree, funcs matcherFuncs) error {
	switch rule.Matcher {
	case "and", "or":
		m.operator = rule.Matcher
		m.left = &matchersTree{}
		err := m.left.addRule(rule.RuleLeft, funcs)
		if err != nil {
			return fmt.Errorf("error while adding rule %s: %w", rule.Matcher, err)
		}

		m.right = &matchersTree{}
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
			m.matcher = func(req *http.Request) bool {
				return !matcherFunc(req)
			}
		}
	}

	return nil
}
