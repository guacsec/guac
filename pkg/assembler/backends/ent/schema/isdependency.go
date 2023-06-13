package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// IsDependency holds the schema definition for the IsDependency entity.
type IsDependency struct {
	ent.Schema
}

// Fields of the IsDependency.
func (IsDependency) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id"),
		field.Int("dependent_package_id"),
		field.String("version_range"),
		field.String("dependency_type"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the IsDependency.
func (IsDependency) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).
			Field("package_id").
			Unique().
			Required(),
		edge.To("dependent_package", PackageName.Type).
			Field("dependent_package_id").
			Unique().
			Required(),
	}
}

// Indexes of the IsDependency.
func (IsDependency) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("version_range", "dependency_type", "justification", "origin", "collector").
			Edges("package", "dependent_package").
			Unique(),
	}
}
