package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Builder holds the schema definition for the Builder entity.
type Builder struct {
	ent.Schema
}

// Fields of the Builder.
func (Builder) Fields() []ent.Field {
	return []ent.Field{
		field.String("uri").Unique().Immutable().Comment("The URI of the builder, used as a unique identifier in the graph query"),
	}
}

// Edges of the Builder.
func (Builder) Edges() []ent.Edge {
	return nil
}

// Indexes of the BuilderNode.
func (Builder) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("uri").Unique(),
	}
}
