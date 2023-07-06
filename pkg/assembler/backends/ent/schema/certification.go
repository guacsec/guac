package schema

import "entgo.io/ent"

// Certification holds the schema definition for the Certification entity.
type Certification struct {
	ent.Schema
}

// Fields of the Certification.
func (Certification) Fields() []ent.Field {
	return nil
}

// Edges of the Certification.
func (Certification) Edges() []ent.Edge {
	return nil
}
