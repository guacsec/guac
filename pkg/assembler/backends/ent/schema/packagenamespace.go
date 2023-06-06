package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PackageNamespace holds the schema definition for the PackageNamespace entity.
type PackageNamespace struct {
	ent.Schema
}

// Fields of the PackageNamespace.
func (PackageNamespace) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id"),
		field.String("namespace").NotEmpty().Comment("In the pURL representation, each PackageNamespace matches the pkg:<type>/<namespace>/ partial pURL"),
	}
}

// Edges of the PackageNamespace.
func (PackageNamespace) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("package", PackageNode.Type).Required().Field("package_id").Ref("namespaces").Unique(),
		edge.To("names", PackageName.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the PackageNamespace.
func (PackageNamespace) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("namespace").Edges("package").Unique(),
	}
}
