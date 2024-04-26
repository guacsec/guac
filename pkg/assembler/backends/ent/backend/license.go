//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"context"
	stdsql "database/sql"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestLicenses(ctx context.Context, licenses []*model.IDorLicenseInput) ([]string, error) {
	funcName := "IngestLicenses"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkLicense(ctx, client, licenses)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(license.Table, *ids), nil
}

func (b *EntBackend) IngestLicense(ctx context.Context, licenseInput *model.IDorLicenseInput) (string, error) {
	record, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		licenseID, err := upsertLicense(ctx, client, *licenseInput.LicenseInput)
		if err != nil {
			return nil, err
		}

		return licenseID, nil
	})
	if txErr != nil {
		return "", txErr
	}

	return toGlobalID(license.Table, *record), nil
}

func (b *EntBackend) LicenseList(ctx context.Context, licenseSpec model.LicenseSpec, after *string, first *int) (*model.LicenseConnection, error) {
	return nil, fmt.Errorf("not implemented: LicenseList")
}

func (b *EntBackend) Licenses(ctx context.Context, filter *model.LicenseSpec) ([]*model.License, error) {
	if filter == nil {
		filter = &model.LicenseSpec{}
	}
	records, err := getLicenses(ctx, b.client, *filter)
	if err != nil {
		return nil, fmt.Errorf("failed license query with error: %w", err)
	}
	return collect(records, toModelLicense), nil
}

func getLicenses(ctx context.Context, client *ent.Client, filter model.LicenseSpec) ([]*ent.License, error) {
	results, err := client.License.Query().
		Where(licenseQuery(filter)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func upsertBulkLicense(ctx context.Context, tx *ent.Tx, licenseInputs []*model.IDorLicenseInput) (*[]string, error) {
	batches := chunk(licenseInputs, MaxBatchSize)
	ids := make([]string, 0)

	for _, licenses := range batches {
		creates := make([]*ent.LicenseCreate, len(licenses))
		for i, lic := range licenses {
			l := lic
			licenseID := generateUUIDKey([]byte(helpers.GetKey[*model.LicenseInputSpec, string](l.LicenseInput, helpers.LicenseServerKey)))
			creates[i] = generateLicenseCreate(tx, &licenseID, l.LicenseInput)
			ids = append(ids, licenseID.String())
		}

		err := tx.License.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(
					license.FieldName,
					license.FieldInline,
					license.FieldListVersion,
				),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert license node")
		}
	}

	return &ids, nil
}

func generateLicenseCreate(tx *ent.Tx, licenseID *uuid.UUID, licInput *model.LicenseInputSpec) *ent.LicenseCreate {
	return tx.License.Create().
		SetID(*licenseID).
		SetName(licInput.Name).
		SetInline(stringOrEmpty(licInput.Inline)).
		SetListVersion(stringOrEmpty(licInput.ListVersion))
}

func upsertLicense(ctx context.Context, tx *ent.Tx, spec model.LicenseInputSpec) (*string, error) {
	licenseID := generateUUIDKey([]byte(helpers.GetKey[*model.LicenseInputSpec, string](&spec, helpers.LicenseServerKey)))
	insert := generateLicenseCreate(tx, &licenseID, &spec)
	err := insert.
		OnConflict(
			sql.ConflictColumns(
				license.FieldName,
				license.FieldInline,
				license.FieldListVersion,
			),
		).
		DoNothing().
		Exec(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert license node")
		}
	}
	return ptrfrom.String(licenseID.String()), nil
}

func licenseQuery(filter model.LicenseSpec) predicate.License {
	return license.And(
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Name, license.NameEqualFold),
		optionalPredicate(filter.Inline, license.InlineEqualFold),
		optionalPredicate(filter.ListVersion, license.ListVersionEqualFold),
	)
}

func licenseInputQuery(filter model.LicenseInputSpec) predicate.License {
	return licenseQuery(model.LicenseSpec{
		Name:        &filter.Name,
		Inline:      filter.Inline,
		ListVersion: filter.ListVersion,
	})
}

func getLicenseID(ctx context.Context, client *ent.Client, license model.LicenseInputSpec) (uuid.UUID, error) {
	return client.License.Query().Where(licenseInputQuery(license)).OnlyID(ctx)
}

func (b *EntBackend) licenseNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.License.Query().
		Where(licenseQuery(model.LicenseSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeLicenseCertifyLegal] {
		query.
			WithDeclaredInCertifyLegals(func(q *ent.CertifyLegalQuery) {
				getCertifyLegalObject(q)
			}).
			WithDiscoveredInCertifyLegals(func(q *ent.CertifyLegalQuery) {
				getCertifyLegalObject(q)
			})
	}

	licenses, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for license with node ID: %s with error: %w", nodeID, err)
	}

	for _, foundLicense := range licenses {
		declaredCLs, err := foundLicense.DeclaredInCertifyLegals(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get declared license certifyLegal for node ID: %s with error: %w", nodeID, err)
		}
		for _, foundDeclared := range declaredCLs {
			out = append(out, toModelCertifyLegal(foundDeclared))
		}
		disCLs, err := foundLicense.DiscoveredInCertifyLegals(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get discovered license certifyLegal for node ID: %s with error: %w", nodeID, err)
		}
		for _, foundDis := range disCLs {
			out = append(out, toModelCertifyLegal(foundDis))
		}
	}

	return out, nil
}
