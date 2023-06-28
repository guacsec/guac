package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// SourceName holds the schema definition for the SourceName entity.
type SourceName struct {
	ent.Schema
}

// Fields of the SourceName.
func (SourceName) Fields() []ent.Field {
	return []ent.Field{
		field.String("name"),
		field.String("commit").Optional(),
		field.String("tag").Optional(),
		field.Int("namespace_id"),
	}
}

// Edges of the SourceName.
func (SourceName) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("namespace", SourceNamespace.Type).Unique().Required().Field("namespace_id"),
		edge.From("occurrences", Occurrence.Type).Ref("source"),
	}
}

// Indexes of the SourceName.
func (SourceName) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("namespace_id", "name", "commit", "tag").Unique().Annotations(entsql.IndexWhere("commit IS NOT NULL OR tag IS NOT NULL")),
	}
}
