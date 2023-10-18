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

// BillOfMaterials holds the schema definition for the BillOfMaterials (SBOM) entity.
type BillOfMaterials struct {
	ent.Schema
}

// Fields of the SBOM.
func (BillOfMaterials) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id").Optional().Nillable(),
		field.Int("artifact_id").Optional().Nillable(),
		field.String("uri").Comment("SBOM's URI"),
		field.String("algorithm").Comment("Digest algorithm"),
		field.String("digest"),
		field.String("download_location"),
		field.String("origin"),
		field.String("collector").Comment("GUAC collector for the document"),
		field.Time("known_since"),
	}
}

// Edges of the Material.
func (BillOfMaterials) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).Field("package_id").Unique(),
		edge.To("artifact", Artifact.Type).Field("artifact_id").Unique(),
	}
}

// Indexes of the Material.
func (BillOfMaterials) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("algorithm", "digest", "uri", "download_location", "known_since").Edges("package").Unique().
			Annotations(entsql.IndexWhere("package_id IS NOT NULL AND artifact_id IS NULL")).StorageKey("sbom_unique_package"),
		index.Fields("algorithm", "digest", "uri", "download_location", "known_since").Edges("artifact").Unique().
			Annotations(entsql.IndexWhere("package_id IS NULL AND artifact_id IS NOT NULL")).StorageKey("sbom_unique_artifact"),
	}
}
