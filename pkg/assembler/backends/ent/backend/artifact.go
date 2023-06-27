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
		optionalPredicate(spec.Algorithm, artifact.AlgorithmEQ),
		optionalPredicate(spec.Digest, artifact.DigestEQ),
	)
}

func (b *EntBackend) IngestArtifact(ctx context.Context, art *model.ArtifactInputSpec) (*model.Artifact, error) {
	funcName := "IngestArtifact"
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Artifact, error) {
		client := ent.FromContext(ctx)
		return ingestArtifact(ctx, client, art)
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return toModelArtifact(record.Unwrap()), nil
}

func ingestArtifact(ctx context.Context, client *ent.Client, art *model.ArtifactInputSpec) (*ent.Artifact, error) {
	id, err := client.Artifact.Create().
		SetAlgorithm(strings.ToLower(art.Algorithm)).
		SetDigest(strings.ToLower(art.Digest)).
		OnConflict(
			sql.ConflictColumns(
				artifact.FieldAlgorithm,
				artifact.FieldDigest,
			),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.Artifact.Get(ctx, id)
}
