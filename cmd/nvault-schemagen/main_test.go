package main

import (
	"strings"
	"testing"

	"github.com/nstranquist/nvault/crypto"
	"github.com/nstranquist/nvault/wire"
)

func TestRenderUsesGoConstants(t *testing.T) {
	output := render()
	for _, expected := range []string{
		`export type Kind = "` + string(wire.KindSecret) + `" | "` + string(wire.KindParam) + `";`,
		`export const ENVELOPE_FORMAT_V1 = "` + crypto.FormatV1 + `";`,
		`export const ENVELOPE_ALG_V1 = "` + crypto.AlgV1 + `";`,
		"scope: string;",
		"recipient_revision: number;",
		"export interface RecipientPolicyResponse {",
		"export interface PushItem {",
		"expected_version: number;",
		"export interface VersionsResponse {",
		"export interface DeleteResponse {",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("generated output is missing %q", expected)
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	first := render()
	second := render()
	if first != second {
		t.Fatal("render output is not deterministic")
	}
}

func TestGeneratedContentEqualAcceptsGitLineEndings(t *testing.T) {
	output := "first\nsecond\n"
	if !generatedContentEqual([]byte(output), output) {
		t.Fatal("LF content should match")
	}
	if !generatedContentEqual([]byte("first\r\nsecond\r\n"), output) {
		t.Fatal("CRLF checkout content should match canonical LF output")
	}
	if generatedContentEqual([]byte("first\rsecond\r"), output) {
		t.Fatal("lone carriage returns must not be normalized")
	}
	if generatedContentEqual([]byte("first\r\nchanged\r\n"), output) {
		t.Fatal("line-ending normalization must not hide content drift")
	}
}
