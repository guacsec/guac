package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// CertifyVuln holds the schema definition for the CertifyVuln entity.
type CertifyVuln struct {
	ent.Schema
}

// Fields of the Vulnerability.
func (CertifyVuln) Fields() []ent.Field {
	return []ent.Field{
		field.Int("vulnerability_id").Optional().Nillable().Comment("Advisory is one of OSV, GHSA, or CVE, or nil if not vulnerable"),
		field.Int("package_id"),
		field.Time("time_scanned"),
		field.String("db_uri"),
		field.String("db_version"),
		field.String("scanner_uri"),
		field.String("scanner_version"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the Vulnerability.
func (CertifyVuln) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("vulnerability", SecurityAdvisory.Type).Unique().Field("vulnerability_id").Comment("Vulnerability is one of OSV, GHSA, or CVE"),
		edge.To("package", PackageVersion.Type).Unique().Field("package_id").Required(),
	}
}

// Indexes of the Vulnerability.
func (CertifyVuln) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("db_uri", "db_version", "scanner_uri", "scanner_version", "origin", "collector").Edges("vulnerability", "package").Unique().Annotations(entsql.IndexWhere("vulnerability_id IS NOT NULL")),
		index.Fields("db_uri", "db_version", "scanner_uri", "scanner_version", "origin", "collector").Edges("package").Unique().Annotations(entsql.IndexWhere("vulnerability_id IS NULL")),
	}
}
