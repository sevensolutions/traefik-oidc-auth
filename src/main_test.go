package src

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTemplate_mapToJsonArray(t *testing.T) {
	evalContext := map[string]any{
		"claims": map[string]any{
			"roles": []any{"admin", "user", 123},
		},
	}

	template, err := newTemplate().Parse("{{ .claims.roles | withPrefix \"prefix:\" | withSuffix \":suffix\" | mapToJsonArray }}")
	if err != nil {
		t.Fatal(err)
	}
	var renderedValue bytes.Buffer
	err = template.Execute(&renderedValue, evalContext)
	if err != nil {
		t.Fatal(err)
	}

	var result []string
	err = json.Unmarshal(renderedValue.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 elements in the array, got %d", len(result))
	}

	if result[0] != "prefix:admin:suffix" {
		t.Errorf("Expected prefix:admin:suffix at index 0, got %s", result[0])
	}

	if result[1] != "prefix:user:suffix" {
		t.Errorf("Expected prefix:user:suffix at index 1, got %s", result[1])
	}

	if result[2] != "prefix:123:suffix" {
		t.Errorf("Expected prefix:123:suffix at index 2, got %s", result[2])
	}
}
