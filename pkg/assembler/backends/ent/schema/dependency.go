package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Dependency holds the schema definition for the Dependency entity.
type Dependency struct {
	ent.Schema
}

// Annotations of the Dependency.
func (Dependency) Annotations() []schema.Annotation {
	return []schema.Annotation{
		// field.ID("dependent_package_id", "package_id"),
	}
}

// Fields of the Dependency.
func (Dependency) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id"),
		field.Int("dependent_package_id"),
		field.String("version_range"),
		field.Enum("dependency_type").Values("UNSPECIFIED", "DIRECT", "INDIRECT"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the Dependency.
func (Dependency) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).
			Required().
			Field("package_id").
			Unique(),
		edge.To("dependent_package", PackageName.Type).
			Required().
			Field("dependent_package_id").
			Unique(),
	}
}

// Indexes of the Dependency.
func (Dependency) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("version_range", "dependency_type", "justification", "origin", "collector").
			Edges("package", "dependent_package").
			Unique(),
	}
}
