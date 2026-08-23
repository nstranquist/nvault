package strictjson

import "testing"

func TestCheck(t *testing.T) {
	tests := map[string]struct {
		raw  string
		fail bool
	}{
		"valid":             {raw: `{"a":[{"b":true}],"c":null}`},
		"duplicate root":    {raw: `{"a":1,"a":2}`, fail: true},
		"duplicate nested":  {raw: `{"a":{"b":1,"b":2}}`, fail: true},
		"trailing":          {raw: `{} []`, fail: true},
		"malformed":         {raw: `{"a":`, fail: true},
		"excessive nesting": {raw: `[[[[[]]]]]`, fail: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := Check([]byte(test.raw), 3)
			if (err != nil) != test.fail {
				t.Fatalf("Check err=%v fail=%v", err, test.fail)
			}
		})
	}
}
