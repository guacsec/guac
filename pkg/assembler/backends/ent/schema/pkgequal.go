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

// Fields of the PkgEqual.
func (PkgEqual) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_version_id"),
		field.Int("similar_id"),
		field.String("origin"),
		field.String("collector"),
		field.String("justification"),
	}
}

// Edges of the PkgEqual.
func (PkgEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package_a", PackageVersion.Type).Required().Unique().Field("package_version_id"),
		edge.To("package_b", PackageVersion.Type).Required().Unique().Field("similar_id"),
	}
}

// Indexes of the PkgEqual.
func (PkgEqual) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("package_version_id", "similar_id").Unique(),
		index.Fields("package_version_id", "similar_id", "origin", "justification", "collector").Unique(),
	}
}
