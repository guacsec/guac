package ent

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type EntBackend struct {
	backends.Backend
	client *Client
}

func GetBackend(entClient *Client) backends.Backend {
	return &EntBackend{
		client: entClient,
	}
}

func (b *EntBackend) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	query := b.client.Artifact.Query().Order(Asc(artifact.FieldID))

	if artifactSpec != nil {
		if artifactSpec.ID != nil {
			query = query.Where(artifact.ID(*artifactSpec.ID))
		}
		if artifactSpec.Algorithm != nil {
			query = query.Where(artifact.Algorithm(*artifactSpec.Algorithm))
		}
		if artifactSpec.Digest != nil {
			query = query.Where(artifact.Digest(*artifactSpec.Digest))
		}
	} else {
		// FIXME: We limit this to a sane number so as not to blow up the server
		query = query.Limit(100)
	}

	artifacts, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return Transform(artifacts, toArtifact), nil
}
