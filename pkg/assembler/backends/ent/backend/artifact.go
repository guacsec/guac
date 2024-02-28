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
	"crypto/sha256"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/pkg/errors"
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

func (b *EntBackend) IngestArtifacts(ctx context.Context, artifacts []*model.IDorArtifactInput) ([]string, error) {
	funcName := "IngestArtifacts"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkArtifact(ctx, client, artifacts)
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

func (b *EntBackend) IngestArtifact(ctx context.Context, art *model.IDorArtifactInput) (string, error) {
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		return upsertArtifact(ctx, client, art)
	})
	if err != nil {
		return "", err
	}
	return *id, nil
}

func upsertBulkArtifact(ctx context.Context, tx *ent.Tx, artInputs []*model.IDorArtifactInput) (*[]string, error) {
	batches := chunk(artInputs, 100)
	ids := make([]string, 0)

	for _, artifacts := range batches {
		creates := make([]*ent.ArtifactCreate, len(artifacts))
		for i, art := range artifacts {
			artInput := art
			artifactID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(helpers.GetKey[*model.ArtifactInputSpec, string](artInput.ArtifactInput, helpers.ArtifactServerKey)), 5)
			creates[i] = generateArtifactCreate(tx, &artifactID, artInput)

			ids = append(ids, artifactID.String())
		}

		err := tx.Artifact.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(artifact.FieldDigest),
			).
			Ignore().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert artifact node")
		}
	}

	return &ids, nil
}

func generateArtifactCreate(tx *ent.Tx, artifactID *uuid.UUID, art *model.IDorArtifactInput) *ent.ArtifactCreate {
	return tx.Artifact.Create().
		SetID(*artifactID).
		SetAlgorithm(strings.ToLower(art.ArtifactInput.Algorithm)).
		SetDigest(strings.ToLower(art.ArtifactInput.Digest))
}

func upsertArtifact(ctx context.Context, tx *ent.Tx, art *model.IDorArtifactInput) (*string, error) {
	artifactID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(helpers.GetKey[*model.ArtifactInputSpec, string](art.ArtifactInput, helpers.ArtifactServerKey)), 5)
	insert := generateArtifactCreate(tx, &artifactID, art)
	id, err := insert.
		OnConflict(
			sql.ConflictColumns(artifact.FieldDigest),
		).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "upsert artifact")
	}
	return ptrfrom.String(id.String()), nil
}
