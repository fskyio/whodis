package web

import (
	"strings"
	"testing"
)

func TestHighlightJSONPreservesFieldsOrderAndLiterals(t *testing.T) {
	body := []byte(`{"unknown":{"literal":1.2300e+02,"truth":true,"nothing":null},"text":"line\n\u003cscript\u003e"}`)
	tokens, err := highlightJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	var rendered strings.Builder
	classes := make(map[string]bool)
	for _, token := range tokens {
		rendered.WriteString(token.Text)
		classes[token.Class] = true
	}
	got := rendered.String()
	for _, want := range []string{`"unknown"`, `"literal": 1.2300e+02`, `"truth": true`, `"nothing": null`, `"line\n\u003cscript\u003e"`} {
		if !strings.Contains(got, want) {
			t.Errorf("highlighted JSON does not contain %q:\n%s", want, got)
		}
	}
	for _, class := range []string{"key", "string", "number", "boolean", "null", "punctuation"} {
		if !classes[class] {
			t.Errorf("missing token class %q", class)
		}
	}
	if strings.Index(got, `"unknown"`) > strings.Index(got, `"text"`) {
		t.Fatalf("field order changed:\n%s", got)
	}
}

func TestHighlightJSONRejectsInvalidInput(t *testing.T) {
	if _, err := highlightJSON([]byte(`{"broken":`)); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}
