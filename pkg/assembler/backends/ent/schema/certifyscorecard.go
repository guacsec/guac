package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// CertifyScorecard holds the schema definition for the CertifyScorecard entity.
type CertifyScorecard struct {
	ent.Schema
}

// Fields of the CertifyScorecard.
func (CertifyScorecard) Fields() []ent.Field {
	return []ent.Field{
		field.Int("source_id"),
		field.Int("scorecard_id"),
	}
}

// Edges of the CertifyScorecard.
func (CertifyScorecard) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("scorecard", Scorecard.Type).Unique().Required().Ref("certifications").Field("scorecard_id"),
		edge.To("source", SourceName.Type).Unique().Required().Field("source_id"),
	}
}
func (CertifyScorecard) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("source_id", "scorecard_id").Unique(),
	}
}
