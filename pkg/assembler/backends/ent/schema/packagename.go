package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PackageName holds the schema definition for the PackageName entity.
type PackageName struct {
	ent.Schema
}

// Fields of the PackageName.
func (PackageName) Fields() []ent.Field {
	return []ent.Field{
		field.Int("namespace_id"),
		field.String("name").NotEmpty(),
	}
}

// Edges of the PackageName.
func (PackageName) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("namespace", PackageNamespace.Type).Required().Field("namespace_id").Ref("names").Unique(),
	}
}

// Indexes of the PackageName.
func (PackageName) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name").Edges("namespace").Unique(),
	}
}
