package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PkgEqual holds the schema definition for the PkgEqual entity.
type PkgEqual struct {
	ent.Schema
}

// func (PkgEqual) Annotations() []schema.Annotation {
// 	return []schema.Annotation{
// 		field.ID("package_version_id", "equal_package_id"),
// 	}
// }

// Fields of the PkgEqual.
func (PkgEqual) Fields() []ent.Field {
	return []ent.Field{
		// field.Int("package_version_id"),
		// field.Int("equal_package_id"),
		field.String("origin"),
		field.String("collector"),
		field.String("justification"),
		field.String("packages_hash").Comment("An opaque hash of the packages that are equal"),
	}
}

// Edges of the PkgEqual.
func (PkgEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("packages", PackageVersion.Type).Required(),
		// edge.To("package", PackageVersion.Type).Required().Field("equal_package_id").Unique(),
		// edge.To("dependant_package", PackageVersion.Type).Required().Field("package_version_id").Unique(),
	}
}

// Indexes of the PkgEqual.
func (PkgEqual) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("packages_hash", "origin", "justification", "collector").Unique(),
	}
}
