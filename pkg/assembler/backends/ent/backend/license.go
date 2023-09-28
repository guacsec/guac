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

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestLicenses(ctx context.Context, licenses []*model.LicenseInputSpec) ([]*model.License, error) {
	var modelLicenses []*model.License
	for i, license := range licenses {
		modelLicense, err := b.IngestLicense(ctx, license)
		if err != nil {
			return nil, gqlerror.Errorf("IngestLicense failed with element #%v with err: %v", i, err)
		}
		modelLicenses = append(modelLicenses, modelLicense)
	}
	return modelLicenses, nil
}

func (b *EntBackend) IngestLicense(ctx context.Context, license *model.LicenseInputSpec) (*model.License, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)
		licenseID, err := upsertLicense(ctx, client, *license)
		if err != nil {
			return nil, err
		}

		return licenseID, nil
	})
	if err != nil {
		return nil, err
	}

	return &model.License{
		ID: nodeID(*record),
	}, nil
}

func (b *EntBackend) Licenses(ctx context.Context, filter *model.LicenseSpec) ([]*model.License, error) {
	records, err := getLicenses(ctx, b.client, *filter)
	if err != nil {
		return nil, err
	}
	return collect(records, toModelLicense), nil
}

func getLicenses(ctx context.Context, client *ent.Client, filter model.LicenseSpec) ([]*ent.License, error) {
	results, err := client.License.Query().
		Where(licenseQuery(filter)).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func upsertLicense(ctx context.Context, client *ent.Tx, spec model.LicenseInputSpec) (*int, error) {
	conflictColumns := []string{license.FieldName}
	var inLineConflictWhere *sql.Predicate
	if spec.Inline != nil {
		conflictColumns = append(conflictColumns, license.FieldInline)
		inLineConflictWhere = sql.And(sql.NotNull(license.FieldInline))
	} else {
		inLineConflictWhere = sql.And(sql.IsNull(license.FieldInline))
	}
	var listVersionConflictWhere *sql.Predicate
	if spec.ListVersion != nil {
		conflictColumns = append(conflictColumns, license.FieldListVersion)
		listVersionConflictWhere = sql.And(sql.NotNull(license.FieldListVersion))
	} else {
		listVersionConflictWhere = sql.And(sql.IsNull(license.FieldListVersion))
	}
	licenseId, err := client.License.Create().
		SetName(spec.Name).
		SetNillableInline(spec.Inline).
		SetNillableListVersion(spec.ListVersion).
		OnConflict(
			sql.ConflictColumns(conflictColumns...),
			sql.ConflictWhere(sql.And(inLineConflictWhere, listVersionConflictWhere)),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert license node")
		}
		licenseId, err = client.License.Query().
			Where(
				license.NameEQ(spec.Name),
				optionalPredicate(spec.Inline, license.InlineEQ),
				optionalPredicate(spec.ListVersion, license.ListVersionEQ),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get package type")
		}
	}
	return &licenseId, nil
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

func getLicenseID(ctx context.Context, client *ent.Client, license model.LicenseInputSpec) (int, error) {
	return client.License.Query().Where(licenseInputQuery(license)).OnlyID(ctx)
}
