package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// SecurityAdvisory holds the schema definition for the SecurityAdvisory entity.
// This wraps both GHSA and CVE nodes.
type SecurityAdvisory struct {
	ent.Schema
}

// Fields of the GitHubSecurityAdvisory.
func (SecurityAdvisory) Fields() []ent.Field {
	return []ent.Field{
		field.String("ghsa_id").Optional().Nillable(),
		field.String("cve_id").Optional().Nillable(),
		field.Int("cve_year").Optional().Nillable(),
	}
}

// Edges of the GitHubSecurityAdvisory.
func (SecurityAdvisory) Edges() []ent.Edge {
	return nil
}

// Indexes of the GitHubSecurityAdvisory.
func (SecurityAdvisory) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ghsa_id").Unique().Annotations(
			entsql.IndexWhere("ghsa_id IS NOT NULL AND cve_id IS NULL"),
		),
		index.Fields("cve_id").Unique().Annotations(
			entsql.IndexWhere("cve_id IS NOT NULL AND ghsa_id IS NULL"),
		),
	}
}
