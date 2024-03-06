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

	if len(filter.Vulnerabilities) > 2 {
		return nil, fmt.Errorf("too many vulnerability specified in vuln equal filter")
	}

	query := b.client.VulnEqual.Query().
		Where(vulnEqualQuery(filter)).
		WithVulnerabilityA(func(query *ent.VulnerabilityIDQuery) {}).
		WithVulnerabilityB(func(query *ent.VulnerabilityIDQuery) {})
	results, err := query.Limit(MaxPageSize).All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(results, toModelVulnEqual), nil
}

func vulnEqualQuery(filter *model.VulnEqualSpec) predicate.VulnEqual {
	if filter == nil {
		return NoOpSelector()
	}
	where := []predicate.VulnEqual{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Justification, vulnequal.JustificationEQ),
		optionalPredicate(filter.Origin, vulnequal.OriginEQ),
		optionalPredicate(filter.Collector, vulnequal.CollectorEQ),
	}

	if len(filter.Vulnerabilities) == 1 {
		where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(optionalPredicate(filter.Vulnerabilities[0].VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold), optionalPredicate(filter.Vulnerabilities[0].Type, vulnerabilityid.TypeEqualFold)),
			vulnequal.HasVulnerabilityBWith(optionalPredicate(filter.Vulnerabilities[0].VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold), optionalPredicate(filter.Vulnerabilities[0].Type, vulnerabilityid.TypeEqualFold))))

		if filter.Vulnerabilities[0].NoVuln != nil {
			if *filter.Vulnerabilities[0].NoVuln {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeEqualFold(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeEqualFold(NoVuln))))
			} else {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeNEQ(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeNEQ(NoVuln))))
			}
		}
	} else if len(filter.Vulnerabilities) == 2 {
		where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(optionalPredicate(filter.Vulnerabilities[0].VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold), optionalPredicate(filter.Vulnerabilities[0].Type, vulnerabilityid.TypeEqualFold)),
			vulnequal.HasVulnerabilityBWith(optionalPredicate(filter.Vulnerabilities[0].VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold), optionalPredicate(filter.Vulnerabilities[0].Type, vulnerabilityid.TypeEqualFold))))

		where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(optionalPredicate(filter.Vulnerabilities[1].VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold), optionalPredicate(filter.Vulnerabilities[1].Type, vulnerabilityid.TypeEqualFold)),
			vulnequal.HasVulnerabilityBWith(optionalPredicate(filter.Vulnerabilities[1].VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold), optionalPredicate(filter.Vulnerabilities[1].Type, vulnerabilityid.TypeEqualFold))))

		if filter.Vulnerabilities[0].NoVuln != nil {
			if *filter.Vulnerabilities[0].NoVuln {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeEqualFold(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeEqualFold(NoVuln))))
			} else {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeNEQ(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeNEQ(NoVuln))))
			}

		}

		if filter.Vulnerabilities[1].NoVuln != nil {
			if *filter.Vulnerabilities[1].NoVuln {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeEqualFold(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeEqualFold(NoVuln))))
			} else {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeNEQ(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeNEQ(NoVuln))))
			}
		}
	}

	return vulnequal.And(where...)
}

func (b *EntBackend) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	funcName := "IngestVulnEquals"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVulnEquals(ctx, client, vulnerabilities, otherVulnerabilities, vulnEquals)
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

func (b *EntBackend) IngestVulnEqual(ctx context.Context, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqual model.VulnEqualInputSpec) (string, error) {
	id, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		return upsertVulnEquals(ctx, tx, vulnerability, otherVulnerability, vulnEqual)
	})

	if txErr != nil {
		return "", txErr
	}

	return *id, nil
}

func upsertBulkVulnEquals(ctx context.Context, tx *ent.Tx, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		vulnequal.FieldVulnerabilitiesHash,
		vulnequal.FieldVulnID,
		vulnequal.FieldEqualVulnID,
		vulnequal.FieldOrigin,
		vulnequal.FieldCollector,
		vulnequal.FieldJustification,
	}

	batches := chunk(vulnEquals, MaxBatchSize)

	index := 0
	for _, ves := range batches {
		creates := make([]*ent.VulnEqualCreate, len(ves))
		for i, ve := range ves {
			ve := ve
			var err error

			creates[i], err = generateVulnEqualCreate(ctx, tx, vulnerabilities[index], otherVulnerabilities[index], ve)
			if err != nil {
				return nil, gqlerror.Errorf("generateVulnEqualCreate :: %s", err)
			}
			index++
		}

		err := tx.VulnEqual.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert vulnEqual node")
		}
	}
	return &ids, nil
}

func generateVulnEqualCreate(ctx context.Context, tx *ent.Tx, vulnerability *model.IDorVulnerabilityInput, otherVulnerability *model.IDorVulnerabilityInput, ve *model.VulnEqualInputSpec) (*ent.VulnEqualCreate, error) {

	if vulnerability == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vulnEqual")
	}
	if otherVulnerability == nil {
		return nil, fmt.Errorf("otherVulnerability must be specified for vulnEqual")
	}

	vulnEqualCreate := tx.VulnEqual.Create().
		SetCollector(ve.Collector).
		SetJustification(ve.Justification).
		SetOrigin(ve.Origin)

	if vulnerability.VulnerabilityNodeID == nil {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(vulnerability.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(vulnerability.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		vulnerability.VulnerabilityNodeID = ptrfrom.String(foundVulnID.String())
	}

	if otherVulnerability.VulnerabilityNodeID == nil {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(otherVulnerability.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(otherVulnerability.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		otherVulnerability.VulnerabilityNodeID = ptrfrom.String(foundVulnID.String())
	}

	sortedVulns := []model.IDorVulnerabilityInput{*vulnerability, *otherVulnerability}

	sort.SliceStable(sortedVulns, func(i, j int) bool { return *sortedVulns[i].VulnerabilityNodeID < *sortedVulns[j].VulnerabilityNodeID })

	var sortedVulnUUIDs []uuid.UUID
	for _, vuln := range sortedVulns {
		if vuln.VulnerabilityNodeID == nil {
			return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
		}
		vulnID, err := uuid.Parse(*vuln.VulnerabilityNodeID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
		sortedVulnUUIDs = append(sortedVulnUUIDs, vulnID)
	}

	vulnEqualCreate.SetVulnerabilityAID(sortedVulnUUIDs[0])
	vulnEqualCreate.SetVulnerabilityBID(sortedVulnUUIDs[1])

	sortedVulnerabilitiesHash := hashVulnerabilities(sortedVulns)

	vulnEqualCreate.SetVulnerabilitiesHash(sortedVulnerabilitiesHash)

	vulnEqualID, err := guacVulnEqualKey(sortedVulnerabilitiesHash, ve)
	if err != nil {
		return nil, fmt.Errorf("failed to create vulnEqual uuid with error: %w", err)
	}
	vulnEqualCreate.SetID(*vulnEqualID)

	return vulnEqualCreate, nil
}

func upsertVulnEquals(ctx context.Context, tx *ent.Tx, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqualInput model.VulnEqualInputSpec) (*string, error) {

	vulnEqualCreate, err := generateVulnEqualCreate(ctx, tx, &vulnerability, &otherVulnerability, &vulnEqualInput)
	if err != nil {
		return nil, gqlerror.Errorf("generatePkgEqualCreate :: %s", err)
	}

	if id, err := vulnEqualCreate.
		OnConflict(
			sql.ConflictColumns(
				vulnequal.FieldVulnerabilitiesHash,
				vulnequal.FieldVulnID,
				vulnequal.FieldEqualVulnID,
				vulnequal.FieldOrigin,
				vulnequal.FieldCollector,
				vulnequal.FieldJustification,
			),
		).
		Ignore().
		ID(ctx); err != nil {

		return nil, errors.Wrap(err, "upsert vulnEqual node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
}

// hashPackages is used to create a unique key for the M2M edge between PkgEquals <-M2M-> PackageVersions
func hashVulnerabilities(slc []model.IDorVulnerabilityInput) string {
	vulns := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range vulns {
		content.WriteString(*v.VulnerabilityNodeID)
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func toModelVulnEqual(record *ent.VulnEqual) *model.VulnEqual {

	vulnerabilities := []*ent.VulnerabilityID{record.Edges.VulnerabilityA, record.Edges.VulnerabilityB}

	return &model.VulnEqual{
		ID:              record.ID.String(),
		Vulnerabilities: collect(vulnerabilities, toModelVulnerabilityFromVulnerabilityID),
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

func canonicalVulnEqualString(ve *model.VulnEqualInputSpec) string {
	return fmt.Sprintf("%s::%s::%s", ve.Justification, ve.Origin, ve.Collector)
}

// guacVulnEqualKey generates an uuid based on the hash of the inputspec and inputs. vulnEqual ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for vulnEqual node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacVulnEqualKey(sortedVulnHash string, veInput *model.VulnEqualInputSpec) (*uuid.UUID, error) {
	veIDString := fmt.Sprintf("%s::%s?", sortedVulnHash, canonicalVulnEqualString(veInput))

	veID := generateUUIDKey([]byte(veIDString))
	return &veID, nil
}
