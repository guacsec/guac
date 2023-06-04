package ent

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func toArtifact(a *Artifact) *model.Artifact {
	return &model.Artifact{
		ID:        fmt.Sprintf("%d", a.ID),
		Algorithm: a.Algorithm,
		Digest:    a.Digest,
	}
}

func Transform[T any, R any](items []T, transformer func(T) R) []R {
	var out []R
	for _, item := range items {
		out = append(out, transformer(item))
	}
	return out
}
