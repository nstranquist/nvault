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
