package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

func (b *EntBackend) HasSBOM(ctx context.Context, spec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	predicates := []predicate.BillOfMaterials{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(toLowerPtr(spec.Algorithm), billofmaterials.AlgorithmEQ),
		optionalPredicate(toLowerPtr(spec.Digest), billofmaterials.DigestEQ),
		optionalPredicate(spec.URI, billofmaterials.URI),
		optionalPredicate(spec.Collector, billofmaterials.CollectorEQ),
		optionalPredicate(spec.DownloadLocation, billofmaterials.DownloadLocationEQ),
		optionalPredicate(spec.Origin, billofmaterials.OriginEQ),
		billofmaterials.AnnotationsMatchSpec(spec.Annotations),
	}

	if spec.Subject != nil {
		if spec.Subject.Package != nil {
			predicates = append(predicates, billofmaterials.HasPackageWith(packageVersionQuery(spec.Subject.Package)))
		} else if spec.Subject.Artifact != nil {
			predicates = append(predicates, billofmaterials.HasArtifactWith(artifactQueryPredicates(spec.Subject.Artifact)))
		}
	}

	records, err := b.client.BillOfMaterials.Query().
		Where(predicates...).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithArtifact().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return collect(records, toModelHasSBOM), nil
}

func (b *EntBackend) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, spec model.HasSBOMInputSpec) (*model.HasSbom, error) {
	funcName := "IngestHasSbom"
	if err := helper.ValidatePackageOrArtifactInput(&subject, "IngestHasSbom"); err != nil {
		return nil, Errorf("%v ::  %s", funcName, err)
	}

	sbomId, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)

		annotations := make([]model.Annotation, len(spec.Annotations))
		for i, a := range spec.Annotations {
			annotations[i] = model.Annotation{
				Key:   a.Key,
				Value: a.Value,
			}
		}

		sbomCreate := client.BillOfMaterials.Create().
			SetURI(spec.URI).
			SetAlgorithm(strings.ToLower(spec.Algorithm)).
			SetDigest(strings.ToLower(spec.Digest)).
			SetDownloadLocation(spec.DownloadLocation).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector).
			SetAnnotations(annotations)

		conflictColumns := []string{
			billofmaterials.FieldURI,
			billofmaterials.FieldAlgorithm,
			billofmaterials.FieldDigest,
			billofmaterials.FieldDownloadLocation,
		}

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			var err error
			p, err := getPkgVersion(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			sbomCreate.SetPackage(p)
			conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(billofmaterials.FieldPackageID),
				sql.IsNull(billofmaterials.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			var err error
			art, err := client.Artifact.Query().
				Where(artifactQueryInputPredicates(*subject.Artifact)).
				Only(ctx)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			sbomCreate.SetArtifact(art)
			conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(billofmaterials.FieldPackageID),
				sql.NotNull(billofmaterials.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		id, err := sbomCreate.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", funcName, err)
		}
		return &id, nil
	})
	if err != nil {
		return nil, Errorf("%v :: %s", funcName, err)
	}

	sbom, err := b.client.BillOfMaterials.Query().
		Where(billofmaterials.ID(*sbomId)).
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
		return nil, Errorf("%v :: %s", funcName, err)
	}
	return toModelHasSBOM(sbom), nil
}
