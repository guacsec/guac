//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// CertifyLegal holds the schema definition for the CertifyLegal entity.
type CertifyLegal struct {
	ent.Schema
}

// Fields of the CertifyLegal.
func (CertifyLegal) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id").Optional().Nillable(),
		field.Int("source_id").Optional().Nillable(),
		field.String("declared_license"),
		field.String("discovered_license"),
		field.String("attribution"),
		field.String("justification"),
		field.Time("time_scanned"),
		field.String("origin"),
		field.String("collector"),
		field.String("declared_licenses_hash").Comment("An opaque hash of the declared license IDs to ensure uniqueness"),
		field.String("discovered_licenses_hash").Comment("An opaque hash of the discovered license IDs to ensure uniqueness"),
	}
}

// Edges of the CertifyLegal.
func (CertifyLegal) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).Field("package_id").Unique(),
		edge.To("source", SourceName.Type).Field("source_id").Unique(),
		edge.To("declared_licenses", License.Type),
		edge.To("discovered_licenses", License.Type),
	}
}

func (CertifyLegal) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("source_id", "declared_license", "discovered_license", "attribution", "justification", "time_scanned", "origin", "collector", "declared_licenses_hash", "discovered_licenses_hash").
			Unique().
			Annotations(entsql.IndexWhere("package_id IS NULL AND source_id IS NOT NULL")),
		index.Fields("package_id", "declared_license", "discovered_license", "attribution", "justification", "time_scanned", "origin", "collector", "declared_licenses_hash", "discovered_licenses_hash").
			Unique().
			Annotations(entsql.IndexWhere("package_id IS NOT NULL AND source_id IS NULL")),
	}
}
