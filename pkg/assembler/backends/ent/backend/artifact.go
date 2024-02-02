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
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
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

func (b *EntBackend) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]string, error) {
	// funcName := "IngestArtifacts"
	// artsID := make([]string, len(artifacts))

	// eg, ctx := errgroup.WithContext(ctx)
	// for i := range artifacts {
	// 	index := i
	// 	art := artifacts[index]
	// 	concurrently(eg, func() error {
	// 		a, err := b.IngestArtifact(ctx, art)
	// 		if err == nil {
	// 			artsID[index] = a
	// 		}
	// 		return err
	// 	})
	// }
	// if err := eg.Wait(); err != nil {
	// 	return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	// }
	var ids []string
	entArtifactIDs, err := WithinTXSlice(ctx, b.client, func(ctx context.Context) ([]*int, error) {
		client := ent.TxFromContext(ctx)
		return upsertBulkArtifact(ctx, client, artifacts)
	})
	if err != nil {
		return ids, err
	}

	for _, entArtifactID := range entArtifactIDs {
		ids = append(ids, strconv.Itoa(*entArtifactID))
	}
	return ids, nil
}

func (b *EntBackend) IngestArtifact(ctx context.Context, art *model.IDorArtifactInput) (string, error) {
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)
		return upsertArtifact(ctx, client, art.ArtifactInput)
	})
	if err != nil {
		return "", err
	}
	return strconv.Itoa(*id), nil
}

func upsertBulkArtifact(ctx context.Context, client *ent.Tx, artifacts []*model.ArtifactInputSpec) ([]*int, error) {
	var artifactBuilders []*ent.ArtifactCreate
	for _, art := range artifacts {
		artCreate := client.Artifact.Create()
		artCreate.SetAlgorithm(art.Algorithm)
		artCreate.SetDigest(art.Digest)
		artCreate.OnConflict(
			sql.ConflictColumns(artifact.FieldDigest),
		).DoNothing()
		artifactBuilders = append(artifactBuilders, artCreate)
	}

	// would have to query for the artifacts concurrently based on the "artGuacKey" once the bulk ingestion is done
	err := client.Client().Debug().Artifact.CreateBulk(artifactBuilders...).
		OnConflict(sql.ConflictColumns(artifact.FieldDigest)).DoNothing().Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk ingest with error: %w", err)
	}
	return nil, nil
}

func upsertArtifact(ctx context.Context, client *ent.Tx, art *model.ArtifactInputSpec) (*int, error) {
	id, err := client.Artifact.Create().
		SetAlgorithm(strings.ToLower(art.Algorithm)).
		SetDigest(strings.ToLower(art.Digest)).
		OnConflict(
			sql.ConflictColumns(artifact.FieldDigest),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert artifact")
		}
		id, err = client.Artifact.Query().
			Where(artifactQueryInputPredicates(*art)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get artifact")
		}
	}
	return &id, nil
}
