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

// Fields of the Occurrence.
func (Occurrence) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id").Optional().Nillable(),
		field.Int("source_id").Optional().Nillable(),
		field.Int("artifact_id").Comment("The artifact in the relationship"),
		field.String("justification").Comment("Justification for the attested relationship"),
		field.String("origin").Comment("Document from which this attestation is generated from"),
		field.String("collector").Comment("GUAC collector for the document"),
	}
}

// Edges of the Occurrence.
func (Occurrence) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package_version", PackageVersion.Type).Field("package_id").Unique(),
		edge.To("source", SourceName.Type).Field("source_id").Unique(),
		edge.To("artifact", Artifact.Type).Field("artifact_id").Unique().Required(),
	}
}

// Indexes of the Occurrence.
func (Occurrence) Indexes() []ent.Index {
	return []ent.Index{
		// FIXME: (ivanvanderbyl) Unique constraints don't work with NULLs
		index.Fields("justification", "origin", "collector").Edges("source", "package_version", "artifact").Unique().
			// Annotations(entsql.IndexWhere("package_id <> NULL AND source_id is NULL")).
			StorageKey("occurrence_unique_package"),
		// index.Fields("justification", "origin", "collector").Edges("source", "artifact").Unique().
		// Annotations(entsql.IndexWhere("source_id <> NULL AND package_id is NULL")).
		// StorageKey("occurrence_unique_source"),
		//index.Fields("justification", "origin", "collector").Edges("package", "source", "artifact").Unique(),
	}
}
