package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Occurrence holds the schema definition for the Occurrence entity.
type Occurrence struct {
	ent.Schema
}

// func (Occurrence) Annotations() []schema.Annotation {
// 	return []schema.Annotation{
// 		field.ID("subject_id", "artifact_id"),
// 	}
// }

// Fields of the Occurrence.
func (Occurrence) Fields() []ent.Field {
	return []ent.Field{
		// field.Int("subject_id"),
		field.Int("artifact_id").Comment("The artifact in the relationship"),
		field.String("justification").Comment("Justification for the attested relationship"),
		field.String("origin").Comment("Document from which this attestation is generated from"),
		field.String("collector").Comment("GUAC collector for the document"),

		field.Int("source_id").Optional().Nillable(),
		field.Int("package_id").Optional().Nillable(),
	}
}

// Edges of the Occurrence.
func (Occurrence) Edges() []ent.Edge {
	return []ent.Edge{
		// edge.From("subject", OccurrenceSubject.Type).Field("subject_id").Unique().Required().Ref("occurrence"),
		// edge.To("subject", OccurrenceSubject.Type).Unique(),
		edge.To("artifact", Artifact.Type).Field("artifact_id").Unique().Required(),

		edge.To("package", PackageVersion.Type).Unique().Field("package_id"),
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
	}
}

// Indexes of the Occurrence.
func (Occurrence) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("justification", "origin", "collector").
			Edges("artifact", "package").
			Unique().
			StorageKey("occurrence_package_uniq"),
		// Annotations(entsql.IndexWhere("package_id IS NOT NULL AND source_id is NULL")),

		// index.Fields("justification", "origin", "collector").Edges("source", "artifact").Unique().
		// Annotations(entsql.IndexWhere("source_id <> NULL AND package_id is NULL")).
		// StorageKey("occurrence_unique_source"),
		//index.Fields("justification", "origin", "collector").Edges("package", "source", "artifact").Unique(),
	}
}
