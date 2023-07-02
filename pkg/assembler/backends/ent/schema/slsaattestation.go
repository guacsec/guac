package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// SLSAAttestation holds the schema definition for the SLSAAttestation entity.
type SLSAAttestation struct {
	ent.Schema
}

// Annotations of the User.
func (SLSAAttestation) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "slsa_attestations"},
	}
}

// Fields of the SLSA.
func (SLSAAttestation) Fields() []ent.Field {
	return []ent.Field{
		field.String("build_type").Comment("Type of the builder"),
		field.JSON("slsa_predicate", []*model.SLSAPredicate{}).Optional().Comment("Individual predicates found in the attestation"),
		field.String("slsa_version").Comment("Version of the SLSA predicate"),
		field.Time("started_on").Optional().Nillable().Comment("Timestamp of build start time"),
		field.Time("finished_on").Optional().Nillable().Comment("Timestamp of build end time"),
		field.String("origin").Comment("Document from which this attestation is generated from"),
		field.String("collector").Comment("GUAC collector for the document"),
	}
}

// Edges of the SLSA.
func (SLSAAttestation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("built_from", Artifact.Type),
		edge.To("built_by", Builder.Type),
	}
}

// TODO: (ivanvanderbyl) Add indexes for the SLSAAttestation entity.
