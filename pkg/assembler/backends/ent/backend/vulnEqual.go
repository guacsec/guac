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
	"bytes"
	"context"
	"crypto/sha1"
	stdsql "database/sql"
	"fmt"
	"sort"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
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
		where = append(where, vulnequal.HasVulnerabilityIdsWith(optionalPredicate(vulnID.Type, vulnerabilityid.TypeEqualFold)))
		if vulnID.NoVuln != nil {
			if *vulnID.NoVuln {
				where = append(where, vulnequal.HasVulnerabilityIdsWith(vulnerabilityid.TypeEqualFold(NoVuln)))
			} else {
				where = append(where, vulnequal.HasVulnerabilityIdsWith(vulnerabilityid.TypeNEQ(NoVuln)))
			}
		}
	}

	query := b.client.VulnEqual.Query().
		Where(where...).
		WithVulnerabilityIds(func(query *ent.VulnerabilityIDQuery) {
			query.Order(vulnerabilityid.ByID())
		})

	results, err := query.Limit(MaxPageSize).All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(results, toModelVulnEqual), nil
}

func (b *EntBackend) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	funcName := "IngestVulnEquals"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVulnEquals(ctx, client, vulnerabilities, otherVulnerabilities, vulnEquals)
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

func (b *EntBackend) IngestVulnEqual(ctx context.Context, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqual model.VulnEqualInputSpec) (string, error) {
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		return upsertVulnEquals(ctx, tx, vulnerability, otherVulnerability, vulnEqual)
	})

	if err != nil {
		return "", err
	}

	return *id, nil
}

func upsertBulkVulnEquals(ctx context.Context, client *ent.Tx, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		vulnequal.FieldVulnerabilitiesHash,
		vulnequal.FieldOrigin,
		vulnequal.FieldCollector,
		vulnequal.FieldJustification,
	}

	batches := chunk(vulnEquals, 100)

	index := 0
	for _, ves := range batches {
		creates := make([]*ent.VulnEqualCreate, len(ves))
		for i, ve := range ves {

			sortedVulns := []model.IDorVulnerabilityInput{*vulnerabilities[index], *otherVulnerabilities[index]}

			sort.SliceStable(sortedVulns, func(i, j int) bool { return *sortedVulns[i].VulnerabilityNodeID < *sortedVulns[j].VulnerabilityNodeID })

			var sortedVulnIDs []uuid.UUID
			for _, vuln := range sortedVulns {
				if vuln.VulnerabilityNodeID == nil {
					return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
				}
				vulnID, err := uuid.Parse(*vuln.VulnerabilityNodeID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
				}
				sortedVulnIDs = append(sortedVulnIDs, vulnID)
			}

			creates[i] = client.VulnEqual.Create().
				AddVulnerabilityIDIDs(sortedVulnIDs...).
				SetVulnerabilitiesHash(hashVulnerabilities(sortedVulns)).
				SetCollector(ve.Collector).
				SetJustification(ve.Justification).
				SetOrigin(ve.Origin)

			index++
		}

		err := client.VulnEqual.CreateBulk(creates...).
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

func upsertVulnEquals(ctx context.Context, client *ent.Tx, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqualInput model.VulnEqualInputSpec) (*string, error) {

	sortedVulns := []model.IDorVulnerabilityInput{vulnerability, otherVulnerability}

	sort.SliceStable(sortedVulns, func(i, j int) bool { return *sortedVulns[i].VulnerabilityNodeID < *sortedVulns[j].VulnerabilityNodeID })

	var sortedVulnIDs []uuid.UUID
	for _, vuln := range sortedVulns {
		if vuln.VulnerabilityNodeID == nil {
			return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
		}
		vulnID, err := uuid.Parse(*vuln.VulnerabilityNodeID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
		sortedVulnIDs = append(sortedVulnIDs, vulnID)
	}

	_, err := client.VulnEqual.Create().
		AddVulnerabilityIDIDs(sortedVulnIDs...).
		SetVulnerabilitiesHash(hashVulnerabilities(sortedVulns)).
		SetCollector(vulnEqualInput.Collector).
		SetJustification(vulnEqualInput.Justification).
		SetOrigin(vulnEqualInput.Origin).
		OnConflict(
			sql.ConflictColumns(
				vulnequal.FieldVulnerabilitiesHash,
				vulnequal.FieldOrigin,
				vulnequal.FieldCollector,
				vulnequal.FieldJustification,
			),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsertVulnEquals")
		}
	}

	return ptrfrom.String(""), nil
}

// hashPackages is used to create a unique key for the M2M edge between PkgEquals <-M2M-> PackageVersions
func hashVulnerabilities(slc []model.IDorVulnerabilityInput) string {
	vulns := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range vulns {
		content.WriteString(fmt.Sprintf("%d", v.VulnerabilityNodeID))
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func toModelVulnEqual(record *ent.VulnEqual) *model.VulnEqual {
	return &model.VulnEqual{
		ID:              record.ID.String(),
		Vulnerabilities: collect(record.Edges.VulnerabilityIds, toModelVulnerabilityFromVulnerabilityID),
		Justification:   record.Justification,
		Origin:          record.Origin,
		Collector:       record.Collector,
	}
}

func toModelVulnerabilityFromVulnerabilityID(vulnID *ent.VulnerabilityID) *model.Vulnerability {
	return &model.Vulnerability{
		ID:               fmt.Sprintf("%s:%s", vulnTypeString, vulnID.ID.String()),
		Type:             vulnID.Type,
		VulnerabilityIDs: []*model.VulnerabilityID{toModelVulnerabilityID(vulnID)},
	}
}
