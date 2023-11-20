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
	"strconv"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	query := b.client.Artifact.Query().
		Where(artifactQueryPredicates(artifactSpec)).
		Limit(MaxPageSize)

	artifacts, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return collect(artifacts, toModelArtifact), nil
}

func artifactQueryInputPredicates(spec model.ArtifactInputSpec) predicate.Artifact {
	return artifact.And(
		artifact.AlgorithmEqualFold(strings.ToLower(spec.Algorithm)),
		artifact.DigestEqualFold(strings.ToLower(spec.Digest)),
	)
}

func artifactQueryPredicates(spec *model.ArtifactSpec) predicate.Artifact {
	return artifact.And(
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Algorithm, artifact.AlgorithmEqualFold),
		optionalPredicate(spec.Digest, artifact.DigestEqualFold),
	)
}

func toLowerPtr(s *string) *string {
	if s == nil {
		return nil
	}
	lower := strings.ToLower(*s)
	return &lower
}

func (b *EntBackend) IngestArtifactIDs(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]string, error) {
	funcName := "IngestArtifactIDs"
	records, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := ingestArtifacts(ctx, client, artifacts)
		if err != nil {
			return nil, err
		}

		return slc, nil
	})

	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return *records, nil
}

func (b *EntBackend) IngestArtifactID(ctx context.Context, art *model.ArtifactInputSpec) (string, error) {
	records, err := b.IngestArtifactIDs(ctx, []*model.ArtifactInputSpec{art})
	if err != nil {
		return "", err
	}

	if len(records) == 0 {
		return "", Errorf("no records returned")
	}

	return records[0], nil
}

func ingestArtifacts(ctx context.Context, client *ent.Tx, artifacts []*model.ArtifactInputSpec) (*[]string, error) {
	batches := chunk(artifacts, 100)
	ids := make([]int, 0)

	for _, artifacts := range batches {
		creates := make([]*ent.ArtifactCreate, len(artifacts))
		predicates := make([]predicate.Artifact, len(artifacts))
		for i, art := range artifacts {
			creates[i] = client.Artifact.Create().
				SetAlgorithm(strings.ToLower(art.Algorithm)).
				SetDigest(strings.ToLower(art.Digest))
		}

		err := client.Artifact.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(artifact.FieldDigest),
			).
			UpdateNewValues().
			Exec(ctx)
		if err != nil {
			return nil, err
		}

		for i, art := range artifacts {
			predicates[i] = artifactQueryInputPredicates(*art)
		}

		newRecords, err := client.Artifact.Query().Where(artifact.Or(predicates...)).IDs(ctx)
		if err != nil {
			return nil, err
		}

		ids = append(ids, newRecords...)
	}
	result := make([]string, len(ids))
	for i := range ids {
		result[i] = strconv.Itoa(ids[i])
	}
	return &result, nil
}
