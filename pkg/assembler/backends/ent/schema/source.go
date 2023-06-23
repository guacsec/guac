package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Source holds the schema definition for the Source entity.
type Source struct {
	ent.Schema
}

// Fields of the Source.
func (Source) Fields() []ent.Field {
	return []ent.Field{
		field.String("type"),
		field.String("namespace").Optional(),
		field.String("name").Optional(),
		field.String("tag").Optional(),
		field.String("commit").Optional(),
	}
}

// Edges of the Source.
func (Source) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("namespaces", SourceNamespace.Type).Ref("source"),
	}
}

// Indexes of the Source.
func (Source) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type", "namespace", "name", "tag", "commit").Unique(),
	}
}
