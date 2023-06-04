package ent

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/buildernode"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type EntBackend struct {
	backends.Backend
	client *Client
}

type Args struct {
	entClient *Client
}

func WithEntClient(client *Client) backends.BackendArgs {
	return Args{entClient: client}
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	be := &EntBackend{}
	if args, ok := args.(Args); ok {
		be.client = args.entClient
	} else {
		return nil, fmt.Errorf("invalid args type")
	}

	return be, nil
}

func (b *EntBackend) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	query := b.client.Artifact.Query().Order(Asc(artifact.FieldID))

	if artifactSpec != nil {
		if artifactSpec.ID != nil {
			query.Where(IDEQ(artifactSpec.ID))
		}
		if artifactSpec.Algorithm != nil {
			query.Where(artifact.Algorithm(*artifactSpec.Algorithm))
		}
		if artifactSpec.Digest != nil {
			query.Where(artifact.Digest(*artifactSpec.Digest))
		}
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

func (b *EntBackend) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	art, err := WithinTX(ctx, b.client, func(ctx context.Context) (*Artifact, error) {
		client := FromContext(ctx)
		// TODO: Use upsert here
		return client.Artifact.Create().
			SetAlgorithm(artifact.Algorithm).
			SetDigest(artifact.Digest).
			Save(ctx)
	})
	if err != nil {
		return nil, err
	}
	return toModelArtifact(art), nil
}

func (b *EntBackend) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	query := b.client.BuilderNode.Query().Order(Asc(buildernode.FieldID))

	if builderSpec != nil {
		if builderSpec.URI != nil {
			query.Where(buildernode.URI(*builderSpec.URI))
		}

		if builderSpec.ID != nil {
			query.Where(IDEQ(builderSpec.ID))
		}
	} else {
		query.Limit(100)
	}

	builders, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(builders, toModelBuilder), nil
}

func (b *EntBackend) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*BuilderNode, error) {
		client := FromContext(ctx)
		// TODO: Use upsert here
		return client.BuilderNode.Create().
			SetURI(builder.URI).
			Save(ctx)
	})
	if err != nil {
		return nil, err
	}
	return toModelBuilder(record), nil
}
