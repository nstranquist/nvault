package wire

import "testing"

func TestCloudAAD(t *testing.T) {
	value, err := CloudAAD("org_123", "env_456", "global", "DB_URL")
	if err != nil {
		t.Fatal(err)
	}
	if value != "org_123/env_456/global/DB_URL" {
		t.Fatalf("value=%q", value)
	}
	for _, test := range [][4]string{
		{"", "env", "global", "KEY"},
		{"org/other", "env", "global", "KEY"},
		{"org", "env", "bad/scope", "KEY"},
		{"org", "env", "global", "bad/key"},
	} {
		if _, err := CloudAAD(test[0], test[1], test[2], test[3]); err == nil {
			t.Fatalf("CloudAAD%q succeeded", test)
		}
	}
}
