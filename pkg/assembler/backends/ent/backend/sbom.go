package backend

import (
	"context"
	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sbom"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"strings"
)

func (b *EntBackend) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error) {
	funcName := "IngestHasSbom"
	if err := helper.ValidatePackageOrArtifactInput(&subject, "IngestHasSbom"); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	sbomId, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)
		algorithm := strings.ToLower(hasSbom.Algorithm)
		digest := strings.ToLower(hasSbom.Digest)

		sbomCreate := client.SBOM.Create().
			SetURI(hasSbom.URI).
			SetAlgorithm(algorithm).
			SetDigest(digest).
			SetDownloadLocation(hasSbom.DownloadLocation).
			SetOrigin(hasSbom.Origin).
			SetCollector(hasSbom.Collector)

		sbomConflictColumns := []string{
			sbom.FieldURI,
			sbom.FieldAlgorithm,
			sbom.FieldDigest,
		}

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			var err error
			p, err := upsertPackage(ctx, client, *subject.Package)
			if err != nil {
				return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
			}
			_, err = client.PackageVersion.Get(ctx, p.ID)
			if err != nil {
				return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
			}
			sbomCreate.SetPackage(p)
			sbomConflictColumns = append(sbomConflictColumns, sbom.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(sbom.FieldPackageID),
				sql.IsNull(sbom.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			var err error
			art, err := client.Artifact.Query().
				Where(artifactQueryFromInputSpec(*subject.Artifact)).
				Only(ctx)
			if err != nil {
				return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
			}
			sbomCreate.SetArtifact(art)
			sbomConflictColumns = append(sbomConflictColumns, sbom.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(sbom.FieldPackageID),
				sql.NotNull(sbom.FieldArtifactID),
			)
		} else {
			return nil, gqlerror.Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		id, err := sbomCreate.
			OnConflict(
				sql.ConflictColumns(sbomConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			UpdateNewValues().
			ID(ctx)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	s, err := b.client.SBOM.Query().
		Where(sbom.ID(*sbomId)).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithArtifact().
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return toModelHasSbom(s), nil
}
