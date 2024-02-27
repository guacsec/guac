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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitymetadata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) VulnerabilityMetadata(ctx context.Context, filter *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {

	records, err := b.client.VulnerabilityMetadata.Query().
		Where(vulnerabilityMetadataPredicate(filter)).
		Limit(MaxPageSize).
		WithVulnerabilityID(func(q *ent.VulnerabilityIDQuery) {}).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VulnerabilityMetadata :: %s", err)
	}

	return collect(records, toModelVulnerabilityMetadata), nil
}

func (b *EntBackend) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.IDorVulnerabilityInput, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertVulnerabilityMetadata(ctx, ent.TxFromContext(ctx), vulnerability, vulnerabilityMetadata)
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute IngestVulnerabilityMetadata :: %s", err)
	}

	return *recordID, nil
}

func (b *EntBackend) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	funcName := "IngestBulkVulnerabilityMetadata"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVulnerabilityMetadata(ctx, client, vulnerabilities, vulnerabilityMetadataList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return *ids, nil
}

func vulnerabilityMetadataPredicate(filter *model.VulnerabilityMetadataSpec) predicate.VulnerabilityMetadata {
	predicates := []predicate.VulnerabilityMetadata{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Timestamp, vulnerabilitymetadata.TimestampGTE),
		optionalPredicate(filter.Origin, vulnerabilitymetadata.OriginEQ),
		optionalPredicate(filter.Collector, vulnerabilitymetadata.CollectorEQ),
	}

	if filter.ScoreType != nil {
		predicates = append(predicates,
			optionalPredicate(ptrfrom.Any(vulnerabilitymetadata.ScoreType(*filter.ScoreType)), vulnerabilitymetadata.ScoreTypeEQ),
		)
	}

	var comparator predicate.VulnerabilityMetadata
	if filter.Comparator != nil {
		switch *filter.Comparator {
		case model.ComparatorGreater:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueGT)
		case model.ComparatorEqual:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueEQ)
		case model.ComparatorLess:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueLT)
		case model.ComparatorGreaterEqual:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueGTE)
		case model.ComparatorLessEqual:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueLTE)
		}
	} else {
		comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueEQ)
	}
	predicates = append(predicates, comparator)

	if filter.Vulnerability != nil {
		predicates = append(predicates,
			vulnerabilitymetadata.HasVulnerabilityIDWith(
				optionalPredicate(filter.Vulnerability.VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold),
				optionalPredicate(filter.Vulnerability.ID, IDEQ),
				optionalPredicate(filter.Vulnerability.Type, vulnerabilityid.TypeEqualFold),
			),
		)
		if filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {
			predicates = append(predicates,
				vulnerabilitymetadata.HasVulnerabilityIDWith(
					vulnerabilityid.TypeEqualFold(NoVuln),
				),
			)
		}
	}
	return vulnerabilitymetadata.And(predicates...)
}

func upsertBulkVulnerabilityMetadata(ctx context.Context, tx *ent.Tx, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		vulnerabilitymetadata.FieldVulnerabilityIDID,
		vulnerabilitymetadata.FieldScoreType,
		vulnerabilitymetadata.FieldScoreValue,
		vulnerabilitymetadata.FieldTimestamp,
		vulnerabilitymetadata.FieldOrigin,
		vulnerabilitymetadata.FieldCollector,
	}

	batches := chunk(vulnerabilityMetadataList, 100)

	index := 0
	for _, vml := range batches {
		creates := make([]*ent.VulnerabilityMetadataCreate, len(vml))
		for i, vm := range vml {
			vm := vm
			var err error

			creates[i], err = generateVulnMetadataCreate(tx, vulnerabilities[index], vm)
			if err != nil {
				return nil, gqlerror.Errorf("generateVulnEqualCreate :: %s", err)
			}
			index++
		}

		err := tx.VulnerabilityMetadata.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ids, nil
}

func generateVulnMetadataCreate(tx *ent.Tx, vulnerability *model.IDorVulnerabilityInput, scorecard *model.VulnerabilityMetadataInputSpec) (*ent.VulnerabilityMetadataCreate, error) {

	if vulnerability == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vulnMetadata")
	}
	if vulnerability.VulnerabilityNodeID == nil {
		return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
	}
	vulnID, err := uuid.Parse(*vulnerability.VulnerabilityNodeID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
	}

	vulnMetadataCreate := tx.VulnerabilityMetadata.Create()

	vulnMetadataCreate.
		SetVulnerabilityIDID(vulnID).
		SetScoreType(vulnerabilitymetadata.ScoreType(scorecard.ScoreType)).
		SetScoreValue(scorecard.ScoreValue).
		SetTimestamp(scorecard.Timestamp.UTC()).
		SetOrigin(scorecard.Origin).
		SetCollector(scorecard.Collector)

	return vulnMetadataCreate, nil
}

func upsertVulnerabilityMetadata(ctx context.Context, tx *ent.Tx, vulnerability model.IDorVulnerabilityInput, spec model.VulnerabilityMetadataInputSpec) (*string, error) {
	conflictColumns := []string{
		vulnerabilitymetadata.FieldVulnerabilityIDID,
		vulnerabilitymetadata.FieldScoreType,
		vulnerabilitymetadata.FieldScoreValue,
		vulnerabilitymetadata.FieldTimestamp,
		vulnerabilitymetadata.FieldOrigin,
		vulnerabilitymetadata.FieldCollector,
	}

	insert, err := generateVulnMetadataCreate(tx, &vulnerability, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateVulnMetadataCreate :: %s", err)

	}
	if _, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
	).
		DoNothing().
		ID(ctx); err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert VulnerabilityMetadata node")
		}
	}

	return ptrfrom.String(""), nil
}

func toModelVulnerabilityMetadata(v *ent.VulnerabilityMetadata) *model.VulnerabilityMetadata {
	return &model.VulnerabilityMetadata{
		ID: v.ID.String(),
		Vulnerability: &model.Vulnerability{
			ID:   fmt.Sprintf("%s:%s", vulnTypeString, v.Edges.VulnerabilityID.ID.String()),
			Type: v.Edges.VulnerabilityID.Type,
			VulnerabilityIDs: []*model.VulnerabilityID{
				{
					ID:              v.Edges.VulnerabilityID.ID.String(),
					VulnerabilityID: v.Edges.VulnerabilityID.VulnerabilityID,
				},
			},
		},
		ScoreType:  model.VulnerabilityScoreType(v.ScoreType),
		ScoreValue: v.ScoreValue,
		Timestamp:  v.Timestamp,
		Origin:     v.Origin,
		Collector:  v.Collector,
	}
}
