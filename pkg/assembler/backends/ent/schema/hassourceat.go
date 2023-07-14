package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// HasSourceAt holds the schema definition for the HasSourceAt entity.
type HasSourceAt struct {
	ent.Schema
}

// Fields of the HasSourceAt.
func (HasSourceAt) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_version_id").Optional().Nillable(),
		field.Int("package_name_id").Optional().Nillable(),
		field.Int("source_id"),
		field.Time("known_since"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the HasSourceAt.
func (HasSourceAt) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package_version", PackageVersion.Type).Field("package_version_id").Unique(),
		edge.To("all_versions", PackageName.Type).Field("package_name_id").Unique(),
		edge.To("source", SourceName.Type).Field("source_id").Unique().Required(),
	}
}

func (HasSourceAt) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("source_id", "package_version_id", "justification").Unique().Annotations(entsql.IndexWhere("package_version_id IS NOT NULL AND package_name_id IS NULL")),
		index.Fields("source_id", "package_name_id", "justification").Unique().Annotations(entsql.IndexWhere("package_name_id IS NOT NULL AND package_version_id IS NULL")),
		index.Fields("known_since"),
	}
}
