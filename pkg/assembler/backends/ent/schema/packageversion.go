package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PackageVersion holds the schema definition for the PackageVersion entity.
type PackageVersion struct {
	ent.Schema
}

// Fields of the PackageVersion.
func (PackageVersion) Fields() []ent.Field {
	return []ent.Field{
		field.Int("name_id"),
		field.String("version"),
		field.String("subpath"),
		field.Strings("qualifiers").Optional(),
		field.String("qualifiers_hash").Comment("A SHA1 of the qualifiers field after sorting keys, used to ensure uniqueness of qualifiers"),
	}
}

// Edges of the PackageVersion.
func (PackageVersion) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("name", PackageName.Type).Required().Field("name_id").Ref("versions").Unique(),
		// edge.To("dependencies", PackageVersion.Type).Through("package", Dependency.Type),
	}
}

// Indexes of the PackageVersion.
func (PackageVersion) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("version", "subpath", "qualifiers_hash").Edges("name").Unique(),
	}
}
