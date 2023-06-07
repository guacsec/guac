package ent

import (
	"context"
	"database/sql"
	"fmt"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/buildernode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/migrate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/pkg/errors"

	// Import regular postgres driver
	_ "github.com/lib/pq"
)

type EntBackend struct {
	backends.Backend
	client *Client
}

type BackendOptions struct {
	DriverName  string
	Address     string
	Debug       bool
	AutoMigrate bool
}

// SetupBackend sets up the ent backend, preparing the database and returning a client
func SetupBackend(ctx context.Context, options BackendOptions) (*Client, error) {
	logger := logging.FromContext(ctx)

	driver := dialect.Postgres
	if options.DriverName != "" {
		driver = options.DriverName
	}
	db, err := sql.Open(driver, options.Address)
	if err != nil {
		return nil, fmt.Errorf("Error opening db: %w", err)
	}

	client := NewClient(Driver(entsql.OpenDB(driver, db)))

	if options.AutoMigrate {
		// Run db migrations
		err = client.Schema.Create(
			ctx,
			migrate.WithDropIndex(true),
			migrate.WithDropColumn(true),
		)
		if err != nil {
			return nil, fmt.Errorf("Error creating ent schema: %w", err)
		}

		logger.Infof("ent migrations complete")
	} else {
		logger.Infof("skipping ent migrations")
	}

	return client, nil
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	be := &EntBackend{}
	if args == nil {
		return nil, fmt.Errorf("invalid args: WithClient is required, got nil")
	}

	if client, ok := args.(*Client); ok {
		be.client = client
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

func (b *EntBackend) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	query := b.client.PackageNode.Query().Order(Asc(packagenode.FieldType))

	if pkgSpec != nil {
		if pkgSpec.Type != nil {
			query.Where(packagenode.Type(*pkgSpec.Type))
		}

		if pkgSpec.Namespace != nil {
			query.Where(packagenode.HasNamespacesWith(packagenamespace.Namespace(*pkgSpec.Namespace)))
			query.WithNamespaces(func(q *PackageNamespaceQuery) {
				q.Where(packagenamespace.Namespace(*pkgSpec.Namespace))

				if pkgSpec.Name != nil {
					q.WithNames(func(q *PackageNameQuery) {
						q.Where(packagename.Name(*pkgSpec.Name))

						// FIXME(ivanvanderbyl): This is incomplete, needs subpath and quals.
						if pkgSpec.Version != nil {
							q.WithVersions(func(q *PackageVersionQuery) {
								q.Where(packageversion.Version(*pkgSpec.Version))
							})
						}
					})
				}
			})
		}

		if pkgSpec.ID != nil {
			query.Where(IDEQ(pkgSpec.ID))
		}
	} else {
		query.Limit(100)
	}

	pkgs, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(pkgs, toModelPackage), nil
}

func (b *EntBackend) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := FromContext(ctx)

		pkgID, err := client.PackageNode.Create().SetType(pkg.Type).
			OnConflict(entsql.ConflictColumns(packagenode.FieldType)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package node")
		}

		nsID, err := client.PackageNamespace.Create().SetPackageID(pkgID).SetNamespace(*pkg.Namespace).
			OnConflict(entsql.ConflictColumns(packagenamespace.FieldNamespace, packagenamespace.FieldPackageID)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package namespace")
		}

		nameID, err := client.PackageName.Create().SetNamespaceID(nsID).SetName(pkg.Name).
			OnConflict(entsql.ConflictColumns(packagename.FieldName, packagename.FieldNamespaceID)).UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package name")
		}

		_, err = client.PackageVersion.Create().
			SetNameID(nameID).
			SetVersion(*pkg.Version).
			SetSubpath(valueOrDefault(pkg.Subpath, "")).
			SetQualifiers(qualifiersToString(pkg.Qualifiers)).
			OnConflict(
				entsql.ConflictColumns(
					packageversion.FieldVersion,
					packageversion.FieldSubpath,
					packageversion.FieldQualifiers,
					packageversion.FieldNameID,
				),
			).
			UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "upsert package version")
		}

		return &pkgID, nil
	})
	if err != nil {
		return nil, err
	}

	// TODO: Figure out if we need to preload the edges from the graphql query
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
