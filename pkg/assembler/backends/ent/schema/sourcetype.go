package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// SourceType holds the schema definition for the SourceType entity.
type SourceType struct {
	ent.Schema
}

// Fields of the SourceType.
func (SourceType) Fields() []ent.Field {
	return []ent.Field{
		field.String("type").Unique(),
	}
}

// Edges of the SourceType.
func (SourceType) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("namespaces", SourceNamespace.Type).Ref("source_type"),
	}
}
