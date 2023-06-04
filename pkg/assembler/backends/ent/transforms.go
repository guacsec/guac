package ent

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func toModelArtifact(a *Artifact) *model.Artifact {
	return &model.Artifact{
		ID:        nodeid(a.ID),
		Algorithm: a.Algorithm,
		Digest:    a.Digest,
	}
}

func toModelBuilder(b *BuilderNode) *model.Builder {
	return &model.Builder{
		ID:  nodeid(b.ID),
		URI: b.URI,
	}
}

// collect is a simple helper to transform collections of a certain type to another type
// using the transform function func(T) R
func collect[T any, R any](items []T, transformer func(T) R) []R {
	out := make([]R, len(items))
	for i, item := range items {
		out[i] = transformer(item)
	}
	return out
}

func nodeid(id int) string {
	return fmt.Sprintf("%d", id)
}
