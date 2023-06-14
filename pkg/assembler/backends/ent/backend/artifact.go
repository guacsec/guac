package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
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

func (b *EntBackend) IngestArtifact(ctx context.Context, art *model.ArtifactInputSpec) (*model.Artifact, error) {
	funcName := "IngestArtifact"
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)
		id, err := client.Artifact.Create().
			SetAlgorithm(art.Algorithm).
			SetDigest(strings.ToLower(art.Digest)).
			OnConflict(
				sql.ConflictColumns(
					artifact.FieldAlgorithm,
					artifact.FieldDigest,
				),
			).
			UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, err
		}
		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	record, err := b.client.Artifact.Query().
		Where(artifact.ID(*recordID)).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return toModelArtifact(record), nil
}
