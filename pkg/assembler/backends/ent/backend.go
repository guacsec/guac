package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/buildernode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
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

func (b *EntBackend) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := FromContext(ctx)

		pkgID, err := client.PackageNode.Create().SetType(pkg.Type).
			OnConflict(sql.ConflictColumns(packagenode.FieldType)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package node")
		}

		nsID, err := client.PackageNamespace.Create().SetPackageID(pkgID).SetNamespace(*pkg.Namespace).
			OnConflict(sql.ConflictColumns(packagenamespace.FieldNamespace, packagenamespace.FieldPackageID)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package namespace")
		}

		nameID, err := client.PackageName.Create().SetNamespaceID(nsID).SetName(pkg.Name).
			OnConflict(sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespaceID)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package name")
		}

		_, err = client.PackageVersion.Create().SetNameID(nameID).SetVersion(*pkg.Version).
			OnConflict(sql.ConflictColumns(packageversion.FieldVersion, packageversion.FieldNameID)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package version")
		}

		return &pkgID, nil
	})
	if err != nil {
		return nil, err
	}

	record, err := b.client.PackageNode.Query().Where(packagenode.ID(*recordID)).
		WithNamespaces(func(q *PackageNamespaceQuery) {
			q.Order(Asc(packagenamespace.FieldNamespace))
			q.WithNames(func(q *PackageNameQuery) {
				q.Order(Asc(packagename.FieldName))
				q.WithVersions(func(q *PackageVersionQuery) {
					q.Order(Asc(packageversion.FieldVersion))
				})
			})
		}).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	return toModelPackage(record), nil
}

func (b *EntBackend) registerPackage(ctx context.Context, packageType, namespace, name, version, subpath string, qualifiers ...string) error {
	pkg, err := b.client.PackageNode.Create().SetType(packageType).Save(ctx)
	if err != nil {
		return err
	}

	ns, err := b.client.PackageNamespace.Create().SetPackage(pkg).SetNamespace(namespace).Save(ctx)
	if err != nil {
		return err
	}

	nameNode, err := b.client.PackageName.Create().SetNamespace(ns).SetName(name).Save(ctx)
	if err != nil {
		return err
	}

	err = b.client.PackageVersion.Create().SetName(nameNode).SetVersion(version).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
