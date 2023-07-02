package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Artifact holds the schema definition for the Artifact entity.
type Artifact struct {
	ent.Schema
}

// Fields of the Artifact.
func (Artifact) Fields() []ent.Field {
	return []ent.Field{
		field.String("algorithm"),
		field.String("digest"),
	}
}

// Edges of the Artifact.
func (Artifact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("occurrences", Occurrence.Type).Ref("artifact").Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.From("sbom", BillOfMaterials.Type).Ref("artifact"),
		edge.From("attestations", SLSAAttestation.Type).Ref("built_from"),
		// edge.To("dependency", Artifact.Type).Annotations(entsql.OnDelete(entsql.Cascade)).From("dependents"),
		// edge.From("source_occurrences", SourceOccurrence.Type).Ref("artifact"),
		// edge.To("sources", Source.Type).Through("source_occurrences", SourceOccurrence.Type),
	}
}

// Indexes of the Artifact.
//
// NOTE: Given the nature of digests, we could treat them as unique identifiers
// with a single index, but currently we index both alg and digest so that it is possible
// to query all artifacts using a specific algorithm.
func (Artifact) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("algorithm", "digest").Unique(),
	}
}
