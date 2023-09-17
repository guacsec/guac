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
		field.Int("vulnerability_id"),
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
		edge.To("vulnerability", VulnerabilityID.Type).Unique().Field("vulnerability_id").Required(),
		edge.To("package", PackageVersion.Type).Unique().Field("package_id").Required(),
	}
}

// Indexes of the Vulnerability.
func (CertifyVuln) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("db_uri", "db_version", "scanner_uri", "scanner_version", "origin", "collector").Edges("vulnerability", "package").Unique(),
	}
}
