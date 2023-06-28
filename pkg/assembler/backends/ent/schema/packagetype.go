package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// PackageType holds the schema definition for the PackageType entity.
type PackageType struct {
	ent.Schema
}

// Fields of the PackageType.
func (PackageType) Fields() []ent.Field {
	return []ent.Field{
		field.String("type").NotEmpty().Unique().Comment("This node matches a pkg:<type> partial pURL"),
	}
}

// Edges of the PackageType.
func (PackageType) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("namespaces", PackageNamespace.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
