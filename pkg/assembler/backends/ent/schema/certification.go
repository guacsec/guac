package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Certification holds the schema definition for the Certification entity.
type Certification struct {
	ent.Schema
}

// Fields of the Certification.
func (Certification) Fields() []ent.Field {
	return []ent.Field{
		// TODO: (ivanvanderbyl) We can reduce the index size by 3/4 if we use a single type field for the source, package_version, package_name, and artifact.
		field.Int("source_id").Optional().Nillable(),
		field.Int("package_version_id").Optional().Nillable(),
		field.Int("package_name_id").Optional().Nillable(),
		field.Int("artifact_id").Optional().Nillable(),
		field.Enum("type").Values("GOOD", "BAD").Default("GOOD"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the Certification.
func (Certification) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
		edge.To("package_version", PackageVersion.Type).Unique().Field("package_version_id"),
		edge.To("all_versions", PackageName.Type).Unique().Field("package_name_id"),
		edge.To("artifact", Artifact.Type).Unique().Field("artifact_id"),
	}
}

func (Certification) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type", "justification", "origin", "collector", "source_id").Unique().Annotations(entsql.IndexWhere("source_id IS NOT NULL AND package_version_id IS NULL AND package_name_id IS NULL AND artifact_id IS NULL")),
		index.Fields("type", "justification", "origin", "collector", "package_version_id").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NOT NULL AND package_name_id IS NULL AND artifact_id IS NULL")),
		index.Fields("type", "justification", "origin", "collector", "package_name_id").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NULL AND package_name_id IS NOT NULL AND artifact_id IS NULL")),
		index.Fields("type", "justification", "origin", "collector", "artifact_id").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NULL AND package_name_id IS NULL AND artifact_id IS NOT NULL")),
	}
}
