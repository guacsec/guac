package schema

import "entgo.io/ent"

// SLSA holds the schema definition for the SLSA entity.
type SLSA struct {
	ent.Schema
}

// Fields of the SLSA.
func (SLSA) Fields() []ent.Field {
	return nil
}

// Edges of the SLSA.
func (SLSA) Edges() []ent.Edge {
	return nil
}
