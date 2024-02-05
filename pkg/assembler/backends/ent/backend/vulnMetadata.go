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
	"strconv"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitymetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitytype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) VulnerabilityMetadata(ctx context.Context, filter *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {

	records, err := b.client.VulnerabilityMetadata.Query().
		Where(vulnerabilityMetadataPredicate(filter)).
		Limit(MaxPageSize).
		WithVulnerabilityID(func(q *ent.VulnerabilityIDQuery) {
			q.WithType()
		}).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VulnerabilityMetadata :: %s", err)
	}

	return collect(records, toModelVulnerabilityMetadata), nil
}

func (b *EntBackend) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		return upsertVulnerabilityMetadata(ctx, ent.TxFromContext(ctx), vulnerability, vulnerabilityMetadata)
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute IngestVulnerabilityMetadata :: %s", err)
	}

	return strconv.Itoa(*recordID), nil
}

func (b *EntBackend) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	var results []string
	for i := range vulnerabilityMetadataList {
		hm, err := b.IngestVulnerabilityMetadata(ctx, *vulnerabilities[i], *vulnerabilityMetadataList[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestBulkVulnerabilityMetadata failed with element #%v with err: %v", i, err)
		}
		results = append(results, hm)
	}
	return results, nil
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
				vulnerabilityid.HasTypeWith(
					optionalPredicate(filter.Vulnerability.ID, IDEQ),
					optionalPredicate(filter.Vulnerability.Type, vulnerabilitytype.TypeEqualFold),
				),
			),
		)
		if filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {
			predicates = append(predicates,
				vulnerabilitymetadata.HasVulnerabilityIDWith(
					vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(NoVuln)),
				),
			)
		}
	}
	return vulnerabilitymetadata.And(predicates...)
}

func upsertVulnerabilityMetadata(ctx context.Context, client *ent.Tx, vulnerability model.VulnerabilityInputSpec, spec model.VulnerabilityMetadataInputSpec) (*int, error) {
	vulnerabilityRecordID, err := client.VulnerabilityID.Query().
		Where(
			vulnerabilityid.VulnerabilityIDEqualFold(vulnerability.VulnerabilityID),
			vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(vulnerability.Type)),
		).
		OnlyID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get VulnerabilityID")
	}

	insert := client.VulnerabilityMetadata.Create().
		SetVulnerabilityIDID(vulnerabilityRecordID).
		SetScoreType(vulnerabilitymetadata.ScoreType(spec.ScoreType)).
		SetScoreValue(spec.ScoreValue).
		SetTimestamp(spec.Timestamp.UTC()).
		SetOrigin(spec.Origin).
		SetCollector(spec.Collector)

	conflictColumns := []string{
		vulnerabilitymetadata.FieldVulnerabilityIDID,
		vulnerabilitymetadata.FieldScoreType,
		vulnerabilitymetadata.FieldScoreValue,
		vulnerabilitymetadata.FieldTimestamp,
		vulnerabilitymetadata.FieldOrigin,
		vulnerabilitymetadata.FieldCollector,
	}
	var conflictWhere *sql.Predicate

	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert VulnerabilityMetadata node")
		}
		id, err = client.VulnerabilityMetadata.Query().
			Where(vulnerabilityMetadataInputPredicate(vulnerability, spec)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get VulnerabilityMetadata")
		}
	}

	return &id, nil
}

func toModelVulnerabilityMetadata(v *ent.VulnerabilityMetadata) *model.VulnerabilityMetadata {
	return &model.VulnerabilityMetadata{
		ID: nodeID(v.ID),
		Vulnerability: &model.Vulnerability{
			ID:   nodeID(v.Edges.VulnerabilityID.Edges.Type.ID),
			Type: v.Edges.VulnerabilityID.Edges.Type.Type,
			VulnerabilityIDs: []*model.VulnerabilityID{
				{
					ID:              nodeID(v.Edges.VulnerabilityID.ID),
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

func vulnerabilityMetadataInputPredicate(vulnerability model.VulnerabilityInputSpec, filter model.VulnerabilityMetadataInputSpec) predicate.VulnerabilityMetadata {
	return vulnerabilityMetadataPredicate(&model.VulnerabilityMetadataSpec{
		Vulnerability: &model.VulnerabilitySpec{
			Type:            &vulnerability.Type,
			VulnerabilityID: &vulnerability.VulnerabilityID,
		},
		ScoreType:  &filter.ScoreType,
		ScoreValue: &filter.ScoreValue,
		Timestamp:  &filter.Timestamp,
		Origin:     &filter.Origin,
		Collector:  &filter.Collector,
	})
}
