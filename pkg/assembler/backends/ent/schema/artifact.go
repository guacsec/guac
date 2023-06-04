package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
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
		edge.To("dependency", Artifact.Type).Annotations(entsql.OnDelete(entsql.Cascade)).From("dependents"),
	}
}
