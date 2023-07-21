package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	query := b.client.Artifact.Query().
		Where(artifactQueryPredicates(artifactSpec)).
		Limit(MaxPageSize)

	artifacts, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return collect(artifacts, toModelArtifact), nil
}

func artifactQueryInputPredicates(spec model.ArtifactInputSpec) predicate.Artifact {
	return artifact.And(
		artifact.AlgorithmEqualFold(strings.ToLower(spec.Algorithm)),
		artifact.DigestEqualFold(strings.ToLower(spec.Digest)),
	)
}

func artifactQueryPredicates(spec *model.ArtifactSpec) predicate.Artifact {
	return artifact.And(
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Algorithm, artifact.AlgorithmEqualFold),
		optionalPredicate(spec.Digest, artifact.DigestEqualFold),
	)
}

func toLowerPtr(s *string) *string {
	if s == nil {
		return nil
	}
	lower := strings.ToLower(*s)
	return &lower
}

func (b *EntBackend) IngestMaterials(ctx context.Context, materials []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	return b.IngestArtifacts(ctx, materials)
}

func (b *EntBackend) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	funcName := "IngestArtifacts"
	records, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Artifacts, error) {
		client := ent.TxFromContext(ctx)
		slc, err := ingestArtifacts(ctx, client, artifacts)
		if err != nil {
			return nil, err
		}

		return &slc, nil
	})

	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return collect(*records, toModelArtifact), nil
}

func (b *EntBackend) IngestArtifact(ctx context.Context, art *model.ArtifactInputSpec) (*model.Artifact, error) {
	records, err := b.IngestArtifacts(ctx, []*model.ArtifactInputSpec{art})
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, Errorf("no records returned")
	}

	return records[0], nil
}

func ingestArtifacts(ctx context.Context, client *ent.Tx, artifacts []*model.ArtifactInputSpec) (ent.Artifacts, error) {
	batches := chunk(artifacts, 100)
	results := make(ent.Artifacts, 0)

	for _, artifacts := range batches {
		creates := make([]*ent.ArtifactCreate, len(artifacts))
		predicates := make([]predicate.Artifact, len(artifacts))
		for i, art := range artifacts {
			creates[i] = client.Artifact.Create().
				SetAlgorithm(strings.ToLower(art.Algorithm)).
				SetDigest(strings.ToLower(art.Digest))
		}

		err := client.Artifact.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(artifact.FieldDigest),
			).
			UpdateNewValues().
			Exec(ctx)
		if err != nil {
			return nil, err
		}

		for i, art := range artifacts {
			predicates[i] = artifactQueryInputPredicates(*art)
		}

		newRecords, err := client.Artifact.Query().Where(artifact.Or(predicates...)).All(ctx)
		if err != nil {
			return nil, err
		}

		results = append(results, newRecords...)
	}
	return results, nil
}
