package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// SourceNamespace holds the schema definition for the SourceNamespace entity.
type SourceNamespace struct {
	ent.Schema
}

// Fields of the SourceNamespace.
func (SourceNamespace) Fields() []ent.Field {
	return []ent.Field{
		field.String("namespace"),
		field.Int("source_id"),
	}
}

// Edges of the SourceNamespace.
func (SourceNamespace) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("source_type", Source.Type).Unique().Required().Field("source_id"),
		edge.From("names", SourceName.Type).Ref("namespace"),
	}
}

// Indexes of the SourceNamespace.
func (SourceNamespace) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("namespace", "source_id").Unique(),
	}
}
