package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// PackageNode holds the schema definition for the PackageNode entity.
type PackageNode struct {
	ent.Schema
}

// Fields of the PackageNode.
func (PackageNode) Fields() []ent.Field {
	return []ent.Field{
		field.String("type").NotEmpty().Unique().Comment("This node matches a pkg:<type> partial pURL"),
	}
}

// Edges of the PackageNode.
func (PackageNode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("namespaces", PackageNamespace.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
