package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// IsDeployed holds the schema definition for the IsDeployed entity.
type IsDeployed struct {
	ent.Schema
}

// Fields of the IsDeployed.
func (IsDeployed) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.UUID("package_id", getUUIDv7()),
		field.Time("deployed_since"),
		field.Time("deployed_until"),
		field.String("resource_id"),
		field.String("environment"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the IsDeployed.
func (IsDeployed) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).
			Required().
			Field("package_id").
			Unique().Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the IsDeployed.
func (IsDeployed) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("package_id", "resource_id", "environment", "origin", "collector").Unique(),
		index.Fields("package_id"),  // speed up frequently run queries to check for deployments with a certain package ID
		index.Fields("resource_id"), // query via the deployment resource ID
		index.Fields("environment"), // query via the deployment environment
	}
}
