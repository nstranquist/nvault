// Package strictjson rejects ambiguous JSON before a typed decoder reads it.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Check validates one JSON value. It rejects repeated object fields, trailing
// values, and nesting deeper than maximumDepth.
func Check(raw []byte, maximumDepth int) error {
	if maximumDepth < 1 {
		return errors.New("strictjson: maximum depth must be positive")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var scanValue func(int) error
	scanValue = func(depth int) error {
		if depth > maximumDepth {
			return fmt.Errorf("JSON nesting exceeds %d", maximumDepth)
		}
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode JSON: %w", err)
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("decode JSON: %w", err)
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("object field is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON field %q", name)
				}
				seen[name] = struct{}{}
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON: %w", err)
			}
			if closing != json.Delim('}') {
				return errors.New("missing object terminator")
			}
		case '[':
			for decoder.More() {
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON: %w", err)
			}
			if closing != json.Delim(']') {
				return errors.New("missing array terminator")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := scanValue(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}
