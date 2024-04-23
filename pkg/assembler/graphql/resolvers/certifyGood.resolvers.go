package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.45

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestCertifyGood is the resolver for the ingestCertifyGood field.
func (r *mutationResolver) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (string, error) {
	funcName := "IngestCertifyGood"
	if err := validatePackageSourceOrArtifactInput(&subject, funcName); err != nil {
		return "", err
	}
	if certifyGood.KnownSince.IsZero() {
		return "", gqlerror.Errorf("certifyGood.KnownSince is a zero time")
	}
	return r.Backend.IngestCertifyGood(ctx, subject, &pkgMatchType, certifyGood)
}

// IngestCertifyGoods is the resolver for the ingestCertifyGoods field.
func (r *mutationResolver) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]string, error) {
	funcName := "IngestCertifyGoods"
	valuesDefined := 0
	ingestedCertifyGoodsIDS := []string{}
	if len(subjects.Packages) > 0 {
		if len(subjects.Packages) != len(certifyGoods) {
			return ingestedCertifyGoodsIDS, gqlerror.Errorf("%v :: uneven packages and certifyGoods for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if len(subjects.Artifacts) > 0 {
		if len(subjects.Artifacts) != len(certifyGoods) {
			return ingestedCertifyGoodsIDS, gqlerror.Errorf("%v :: uneven artifacts and certifyGoods for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if len(subjects.Sources) > 0 {
		if len(subjects.Sources) != len(certifyGoods) {
			return ingestedCertifyGoodsIDS, gqlerror.Errorf("%v :: uneven sources and certifyGoods for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return ingestedCertifyGoodsIDS, gqlerror.Errorf("%v :: must specify at most packages, artifacts or sources", funcName)
	}

	for _, certifyGood := range certifyGoods {
		if certifyGood.KnownSince.IsZero() {
			return ingestedCertifyGoodsIDS, gqlerror.Errorf("certifyGoods contains a zero time")
		}
	}

	return r.Backend.IngestCertifyGoods(ctx, subjects, &pkgMatchType, certifyGoods)
}

// CertifyGood is the resolver for the CertifyGood field.
func (r *queryResolver) CertifyGood(ctx context.Context, certifyGoodSpec model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	if err := validatePackageSourceOrArtifactQueryFilter(certifyGoodSpec.Subject); err != nil {
		return nil, gqlerror.Errorf("CertifyGood :: %s", err)
	}
	return r.Backend.CertifyGood(ctx, &certifyGoodSpec)
}
