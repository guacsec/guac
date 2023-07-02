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
	query := b.client.Artifact.Query().Order(ent.Asc(artifact.FieldID))

	if artifactSpec != nil {
		query.Where(optionalPredicate(artifactSpec.ID, IDEQ))
		query.Where(optionalPredicate(artifactSpec.Algorithm, artifact.AlgorithmEQ))
		query.Where(optionalPredicate(artifactSpec.Digest, artifact.DigestEQ))
	} else {
		// FIXME: We limit this to a sane number so as not to blow up the server
		query.Limit(100)
	}

	artifacts, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return collect(artifacts, toModelArtifact), nil
}

func artifactQueryFromInputSpec(spec model.ArtifactInputSpec) predicate.Artifact {
	return artifact.And(
		artifact.Algorithm(strings.ToLower(spec.Algorithm)),
		artifact.Digest(strings.ToLower(spec.Digest)),
	)
}

func artifactQueryFromQuerySpec(spec *model.ArtifactSpec) predicate.Artifact {
	return artifact.And(
		optionalPredicate(spec.ID, IDEQ),
		// FIXME: (ivanvanderbyl) This needs to be converted to lower as well
		optionalPredicate(spec.Algorithm, artifact.AlgorithmEQ),
		optionalPredicate(spec.Digest, artifact.DigestEQ),
	)
}

func (b *EntBackend) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	funcName := "IngestArtifacts"
	records, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Artifacts, error) {
		client := ent.FromContext(ctx)
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

func ingestArtifacts(ctx context.Context, client *ent.Client, artifacts []*model.ArtifactInputSpec) (ent.Artifacts, error) {
	creates := make([]*ent.ArtifactCreate, len(artifacts))
	// TODO: (ivanvanderbyl) Split into batches to ensure we don't reach the max query size

	for i, art := range artifacts {
		creates[i] = client.Artifact.Create().
			SetAlgorithm(strings.ToLower(art.Algorithm)).
			SetDigest(strings.ToLower(art.Digest))
	}

	err := client.Artifact.CreateBulk(creates...).
		OnConflict(
			sql.ConflictColumns(artifact.FieldAlgorithm, artifact.FieldDigest),
		).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	predicates := make([]predicate.Artifact, len(artifacts))
	for i, art := range artifacts {
		predicates[i] = artifactQueryFromInputSpec(*art)
	}
	return client.Artifact.Query().Where(artifact.Or(predicates...)).All(ctx)
}
