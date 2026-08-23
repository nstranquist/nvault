// Package wire defines nvault's shared local and remote value vocabulary.
// The envelope itself lives in package crypto.
package wire

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nstranquist/nvault/crypto"
)

type Kind string

const (
	KindSecret Kind = "secret"
	KindParam  Kind = "param"
)

type ValueType string

const (
	TypeString ValueType = "string"
	TypeInt    ValueType = "int"
	TypeBool   ValueType = "bool"
	TypeJSON   ValueType = "json"
)

// Item is the metadata representation used by clients. Secret values are not
// present in listings.
type Item struct {
	Key       string    `json:"key"`
	Kind      Kind      `json:"kind"`
	Scope     string    `json:"scope"`
	Type      ValueType `json:"type,omitempty"`
	Value     string    `json:"value,omitempty"`
	Version   int       `json:"version,omitempty"`
	UpdatedAt string    `json:"updated_at,omitempty"`
	HasValue  bool      `json:"has_value"`
}

// CloudAAD returns the canonical authenticated slot used by nvault Cloud. Each
// component is one opaque path segment. Slash is rejected so two different
// tenant and slot tuples cannot produce the same associated data.
func CloudAAD(orgID, environmentID, scope, key string) (string, error) {
	segments := []struct {
		name  string
		value string
	}{
		{"organization", orgID},
		{"environment", environmentID},
		{"scope", scope},
		{"key", key},
	}
	for _, segment := range segments {
		if segment.value == "" {
			return "", fmt.Errorf("wire: %s is required", segment.name)
		}
		if strings.ContainsAny(segment.value, "/\x00") {
			return "", fmt.Errorf("wire: %s must be one path segment", segment.name)
		}
	}
	value := orgID + "/" + environmentID + "/" + scope + "/" + key
	if len(value) > crypto.MaxAADSize {
		return "", errors.New("wire: cloud slot exceeds the associated-data size limit")
	}
	return value, nil
}
