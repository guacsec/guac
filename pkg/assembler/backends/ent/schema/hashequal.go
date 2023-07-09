package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// HashEqual holds the schema definition for the HashEqual entity.
type HashEqual struct {
	ent.Schema
}

// Fields of the HashEqual.
func (HashEqual) Fields() []ent.Field {
	return []ent.Field{
		field.String("origin"),
		field.String("collector"),
		field.String("justification"),
	}
}

// Edges of the HashEqual.
func (HashEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("artifacts", Artifact.Type).Required(),
	}
}
