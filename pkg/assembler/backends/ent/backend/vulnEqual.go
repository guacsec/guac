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

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitytype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) VulnEqual(ctx context.Context, filter *model.VulnEqualSpec) ([]*model.VulnEqual, error) {

	var where = []predicate.VulnEqual{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Justification, vulnequal.JustificationEQ),
		optionalPredicate(filter.Origin, vulnequal.OriginEQ),
		optionalPredicate(filter.Collector, vulnequal.CollectorEQ),
	}
	for _, vulnID := range filter.Vulnerabilities {
		where = append(where, vulnequal.HasVulnerabilityIdsWith(optionalPredicate(vulnID.VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold)))
		where = append(where, vulnequal.HasVulnerabilityIdsWith(vulnerabilityid.HasTypeWith(optionalPredicate(vulnID.Type, vulnerabilitytype.TypeEqualFold))))
		if vulnID.NoVuln != nil {
			if *vulnID.NoVuln {
				where = append(where, vulnequal.HasVulnerabilityIdsWith(vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(NoVuln))))
			} else {
				where = append(where, vulnequal.HasVulnerabilityIdsWith(vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeNEQ(NoVuln))))
			}
		}
	}

	query := b.client.VulnEqual.Query().
		Where(where...).
		WithVulnerabilityIds(func(query *ent.VulnerabilityIDQuery) {
			query.WithType().Order(vulnerabilityid.ByID())
		})

	results, err := query.Limit(MaxPageSize).All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(results, toModelVulnEqual), nil
}

func (b *EntBackend) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, otherVulnerabilities []*model.VulnerabilityInputSpec, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	var ids []string
	for i, vulnEqual := range vulnEquals {
		ve, err := b.IngestVulnEqual(ctx, *vulnerabilities[i], *otherVulnerabilities[i], *vulnEqual)
		if err != nil {
			return nil, gqlerror.Errorf("IngestVulnEquals failed with err: %v", err)
		}
		ids = append(ids, ve.ID)
	}
	return ids, nil
}

func (b *EntBackend) IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (*model.VulnEqual, error) {

	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		tx := ent.TxFromContext(ctx)
		return upsertVulnEquals(ctx, tx, vulnerability, otherVulnerability, vulnEqual)
	})

	if err != nil {
		return nil, err
	}

	return &model.VulnEqual{
		ID: nodeID(*id),
	}, nil
}

func upsertVulnEquals(ctx context.Context, client *ent.Tx, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (*int, error) {
	vulnerabilityRecord, err := client.VulnerabilityID.Query().
		Where(
			vulnerabilityid.VulnerabilityIDEqualFold(vulnerability.VulnerabilityID),
			vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(vulnerability.Type)),
		).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	otherVulnerabilityRecord, err := client.VulnerabilityID.Query().
		Where(
			vulnerabilityid.VulnerabilityIDEqualFold(otherVulnerability.VulnerabilityID),
			vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(otherVulnerability.Type)),
		).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	record, err := vulnerabilityRecord.QueryVulnEquals().
		Where(
			vulnequal.HasVulnerabilityIdsWith(
				vulnerabilityid.VulnerabilityIDEqualFold(otherVulnerability.VulnerabilityID),
				vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(otherVulnerability.Type)),
			),
		).
		Only(ctx)
	if ent.MaskNotFound(err) != nil {
		return nil, err
	}

	if record == nil {
		record, err = client.VulnEqual.Create().
			AddVulnerabilityIds(vulnerabilityRecord, otherVulnerabilityRecord).
			SetJustification(vulnEqual.Justification).
			SetOrigin(vulnEqual.Origin).
			SetCollector(vulnEqual.Collector).
			Save(ctx)
		if err != nil {
			return nil, err
		}
	}
	return &record.ID, nil
}
func toModelVulnEqual(record *ent.VulnEqual) *model.VulnEqual {
	return &model.VulnEqual{
		ID:              nodeID(record.ID),
		Vulnerabilities: collect(record.Edges.VulnerabilityIds, toModelVulnerabilityFromVulnerabilityID),
		Justification:   record.Justification,
		Origin:          record.Origin,
		Collector:       record.Collector,
	}
}

func toModelVulnerabilityFromVulnerabilityID(vulnID *ent.VulnerabilityID) *model.Vulnerability {
	if vulnID.Edges.Type != nil {
		return &model.Vulnerability{
			ID:               nodeID(vulnID.Edges.Type.ID),
			Type:             vulnID.Edges.Type.Type,
			VulnerabilityIDs: []*model.VulnerabilityID{toModelVulnerabilityID(vulnID)},
		}
	}
	return nil
}
