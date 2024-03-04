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
	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertVulnerabilityMetadata(ctx, ent.TxFromContext(ctx), vulnerability, vulnerabilityMetadata)
	})
	if txErr != nil {
		return "", fmt.Errorf("failed to execute IngestVulnerabilityMetadata :: %s", txErr)
	}

	return *recordID, nil
}

func (b *EntBackend) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	funcName := "IngestBulkVulnerabilityMetadata"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVulnerabilityMetadata(ctx, client, vulnerabilities, vulnerabilityMetadataList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
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

	batches := chunk(vulnerabilityMetadataList, MaxBatchSize)

	index := 0
	for _, vml := range batches {
		creates := make([]*ent.VulnerabilityMetadataCreate, len(vml))
		for i, vm := range vml {
			vm := vm
			var err error

			creates[i], err = generateVulnMetadataCreate(ctx, tx, vulnerabilities[index], vm)
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
			return nil, errors.Wrap(err, "bulk upsert VulnerabilityMetadata node")
		}
	}

	return &ids, nil
}

func generateVulnMetadataCreate(ctx context.Context, tx *ent.Tx, vuln *model.IDorVulnerabilityInput, metadata *model.VulnerabilityMetadataInputSpec) (*ent.VulnerabilityMetadataCreate, error) {

	if vuln == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vulnMetadata")
	}
	var vulnID uuid.UUID
	if vuln.VulnerabilityNodeID != nil {
		var err error
		vulnID, err = uuid.Parse(*vuln.VulnerabilityNodeID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
	} else {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(vuln.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(vuln.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		vulnID = foundVulnID
	}

	vulnMetadataCreate := tx.VulnerabilityMetadata.Create()

	vulnMetadataCreate.
		SetVulnerabilityIDID(vulnID).
		SetScoreType(vulnerabilitymetadata.ScoreType(metadata.ScoreType)).
		SetScoreValue(metadata.ScoreValue).
		SetTimestamp(metadata.Timestamp.UTC()).
		SetOrigin(metadata.Origin).
		SetCollector(metadata.Collector)

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

	insert, err := generateVulnMetadataCreate(ctx, tx, &vulnerability, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateVulnMetadataCreate :: %s", err)

	}
	if id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
	).
		Ignore().
		ID(ctx); err != nil {
		return nil, errors.Wrap(err, "upsert VulnerabilityMetadata node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
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
