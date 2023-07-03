package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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
		field.JSON("annotations", []model.Annotation{}).Optional(),
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
		index.Fields("algorithm", "digest", "uri", "download_location").Edges("package").Unique().
			Annotations(entsql.IndexWhere("package_id IS NOT NULL AND artifact_id IS NULL")).StorageKey("sbom_unique_package"),
		index.Fields("algorithm", "digest", "uri", "download_location").Edges("artifact").Unique().
			Annotations(entsql.IndexWhere("package_id IS NULL AND artifact_id IS NOT NULL")).StorageKey("sbom_unique_artifact"),
	}
}
