package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OccurrenceSubject holds the schema definition for the OccurrenceSubject entity.
type OccurrenceSubject struct {
	ent.Schema
}

// Fields of the OccurrenceSubject.
func (OccurrenceSubject) Fields() []ent.Field {
	return []ent.Field{
		field.Int("occurrence_id"),
		field.Int("source_id").Optional().Nillable(),
		field.Int("package_id").Optional().Nillable(),
	}
}

// Edges of the OccurrenceSubject.
func (OccurrenceSubject) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("occurrence", Occurrence.Type).Unique().Field("occurrence_id").Required().Ref("subject"),
		edge.To("package", PackageVersion.Type).Unique().Field("package_id"),
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
	}
}

// Indexes of the OccurrenceSubject.
func (OccurrenceSubject) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("source_id").Annotations(entsql.IndexWhere("source_id IS NOT NULL")),
		index.Fields("package_id").Annotations(entsql.IndexWhere("package_id IS NOT NULL")),
		index.Fields("occurrence_id").Unique(),
	}
}
