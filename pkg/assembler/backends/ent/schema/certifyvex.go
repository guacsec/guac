package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// CertifyVex holds the schema definition for the CertifyVex entity.
type CertifyVex struct {
	ent.Schema
}

// Fields of the VEX.
func (CertifyVex) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id").Optional().Nillable(),
		field.Int("artifact_id").Optional().Nillable(),
		field.Int("vulnerability_id").Comment("Vulnerability is one of OSV, GHSA, or CVE, or nil if not vulnerable"),
		field.Time("knownSince"),
		field.String("status"),
		field.String("statement"),
		field.String("statusNotes"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the VEX.
func (CertifyVex) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).Unique().Field("package_id"),
		edge.To("artifact", Artifact.Type).Unique().Field("artifact_id"),
		edge.To("vulnerability", VulnerabilityType.Type).Unique().Required().Field("vulnerability_id").Comment("Vulnerability is one of OSV, GHSA, or CVE"),
	}
}

// Indexes of the VEX.
func (CertifyVex) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("knownSince", "justification", "status", "statement", "statusNotes", "origin", "collector").Edges("vulnerability", "package").Unique().Annotations(entsql.IndexWhere("artifact_id IS NULL")),
		index.Fields("knownSince", "justification", "status", "statement", "statusNotes", "origin", "collector").Edges("vulnerability", "artifact").Unique().Annotations(entsql.IndexWhere("package_id IS NULL")),
	}
}
