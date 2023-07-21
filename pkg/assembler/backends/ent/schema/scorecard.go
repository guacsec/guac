package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Scorecard holds the schema definition for the Scorecard entity.
type Scorecard struct {
	ent.Schema
}

// Fields of the Scorecard.
func (Scorecard) Fields() []ent.Field {
	return []ent.Field{
		field.JSON("checks", []*model.ScorecardCheck{}),
		field.Float("aggregate_score").Default(0).Comment("Overall Scorecard score for the source"),
		field.Time("time_scanned").Default(time.Now),
		field.String("scorecard_version"),
		field.String("scorecard_commit"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the Scorecard.
func (Scorecard) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("certifications", CertifyScorecard.Type),
	}
}

func (Scorecard) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("origin", "collector", "scorecard_version", "scorecard_commit", "aggregate_score").Unique(),
	}
}
