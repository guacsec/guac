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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) HashEqual(ctx context.Context, spec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	if spec == nil {
		return nil, nil
	}

	query := b.client.HashEqual.Query().Where(
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Origin, hashequal.OriginEQ),
		optionalPredicate(spec.Collector, hashequal.CollectorEQ),
		optionalPredicate(spec.Justification, hashequal.JustificationEQ),
	)

	for _, art := range spec.Artifacts {
		query.Where(hashequal.HasArtifactsWith(artifactQueryPredicates(art)))
	}

	records, err := query.
		WithArtifacts().
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelHashEqual), nil
}

func (b *EntBackend) IngestHashEqual(ctx context.Context, artifact model.IDorArtifactInput, equalArtifact model.IDorArtifactInput, spec model.HashEqualInputSpec) (string, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		return upsertHashEqual(ctx, tx, artifact, equalArtifact, spec)
	})
	if err != nil {
		return "", err
	}

	return *record, nil
}

func (b *EntBackend) IngestHashEquals(ctx context.Context, artifacts []*model.IDorArtifactInput, otherArtifacts []*model.IDorArtifactInput, hashEquals []*model.HashEqualInputSpec) ([]string, error) {
	funcName := "IngestHashEquals"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHashEqual(ctx, client, artifacts, otherArtifacts, hashEquals)
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

func upsertBulkHashEqual(ctx context.Context, client *ent.Tx, artifacts []*model.IDorArtifactInput, otherArtifacts []*model.IDorArtifactInput, hashEquals []*model.HashEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		hashequal.FieldArtifactsHash,
		hashequal.FieldOrigin,
		hashequal.FieldCollector,
		hashequal.FieldJustification,
	}

	batches := chunk(hashEquals, 100)

	index := 0
	for _, hes := range batches {
		creates := make([]*ent.HashEqualCreate, len(hes))
		for i, he := range hes {
			creates[i] = client.HashEqual.Create().
				SetArtifactsHash(hashArtifacts([]model.IDorArtifactInput{*artifacts[index], *otherArtifacts[index]})).
				SetJustification(he.Justification).
				SetOrigin(he.Origin).
				SetCollector(he.Collector)

			if artifacts[index].ArtifactID == nil {
				return nil, fmt.Errorf("ArtifactID not specified in IDorArtifactInput")
			}
			artAID, err := uuid.Parse(*artifacts[index].ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}

			if otherArtifacts[index].ArtifactID == nil {
				return nil, fmt.Errorf("ArtifactID not specified in IDorArtifactInput")
			}
			artBID, err := uuid.Parse(*otherArtifacts[index].ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			creates[i].AddArtifactIDs(artAID, artBID)
			index++
		}

		err := client.HashEqual.CreateBulk(creates...).
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

func upsertHashEqual(ctx context.Context, client *ent.Tx, artifactA model.IDorArtifactInput, artifactB model.IDorArtifactInput, spec model.HashEqualInputSpec) (*string, error) {

	if artifactA.ArtifactID == nil {
		return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
	}
	artAID, err := uuid.Parse(*artifactA.ArtifactID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
	}
	// artifactARecord, err := client.Artifact.Get(ctx, artAID)
	// if err != nil {
	// 	return nil, err
	// }

	if artifactB.ArtifactID == nil {
		return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
	}
	artBID, err := uuid.Parse(*artifactB.ArtifactID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
	}

	// record, err := artifactARecord.QuerySame().Where(hashequal.HasArtifactsWith(artifactQueryInputPredicates(*artifactB.ArtifactInput))).Only(ctx)
	// if ent.MaskNotFound(err) != nil {
	// 	return nil, err
	// }

	if _, err := client.HashEqual.Create().
		AddArtifactIDs(artAID, artBID).
		SetArtifactsHash(hashArtifacts([]model.IDorArtifactInput{artifactA, artifactB})).
		SetJustification(spec.Justification).
		SetOrigin(spec.Origin).
		SetCollector(spec.Collector).
		OnConflict(
			sql.ConflictColumns(
				hashequal.FieldArtifactsHash,
				hashequal.FieldOrigin,
				hashequal.FieldCollector,
				hashequal.FieldJustification,
			),
		).
		DoNothing().
		ID(ctx); err != nil {

		return nil, err
	}

	return ptrfrom.String(""), nil
}

// hashArtifacts is used to create a unique key for the M2M edge between HashEquals <-M2M-> artifacts
func hashArtifacts(arts []model.IDorArtifactInput) string {
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	sort.Slice(arts, func(i, j int) bool { return arts[i].ArtifactInput.Digest < arts[j].ArtifactInput.Digest })

	for _, v := range arts {
		content.WriteString(fmt.Sprintf("%d", v.ArtifactID))
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func toModelHashEqual(record *ent.HashEqual) *model.HashEqual {
	return &model.HashEqual{
		ID:            record.ID.String(),
		Artifacts:     collect(record.Edges.Artifacts, toModelArtifact),
		Justification: record.Justification,
		Collector:     record.Collector,
		Origin:        record.Origin,
	}
}
