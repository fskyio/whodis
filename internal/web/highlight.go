package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode"
)

type jsonToken struct {
	Class string
	Text  string
}

func highlightJSON(body []byte) ([]jsonToken, error) {
	var indented bytes.Buffer
	if err := json.Indent(&indented, body, "", "  "); err != nil {
		return nil, err
	}
	data := indented.Bytes()
	var tokens []jsonToken
	for index := 0; index < len(data); {
		start := index
		switch data[index] {
		case '"':
			index++
			for index < len(data) {
				if data[index] == '\\' {
					index += 2
					continue
				}
				if data[index] == '"' {
					index++
					break
				}
				index++
			}
			class := "string"
			lookahead := index
			for lookahead < len(data) && unicode.IsSpace(rune(data[lookahead])) {
				lookahead++
			}
			if lookahead < len(data) && data[lookahead] == ':' {
				class = "key"
			}
			tokens = append(tokens, jsonToken{Class: class, Text: string(data[start:index])})
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			index++
			for index < len(data) && bytes.ContainsRune([]byte("0123456789+-.eE"), rune(data[index])) {
				index++
			}
			tokens = append(tokens, jsonToken{Class: "number", Text: string(data[start:index])})
		case 't', 'f':
			for index < len(data) && data[index] >= 'a' && data[index] <= 'z' {
				index++
			}
			tokens = append(tokens, jsonToken{Class: "boolean", Text: string(data[start:index])})
		case 'n':
			for index < len(data) && data[index] >= 'a' && data[index] <= 'z' {
				index++
			}
			tokens = append(tokens, jsonToken{Class: "null", Text: string(data[start:index])})
		case '{', '}', '[', ']', ':', ',':
			index++
			tokens = append(tokens, jsonToken{Class: "punctuation", Text: string(data[start:index])})
		default:
			index++
			for index < len(data) && !isJSONTokenStart(data[index]) {
				index++
			}
			tokens = append(tokens, jsonToken{Text: string(data[start:index])})
		}
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty JSON document")
	}
	return tokens, nil
}

func isJSONTokenStart(value byte) bool {
	return value == '"' || value == '-' || value >= '0' && value <= '9' || value == 't' || value == 'f' || value == 'n' || bytes.ContainsRune([]byte("{}[]:,"), rune(value))
}
