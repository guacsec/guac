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
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	if artifactSpec == nil {
		artifactSpec = &model.ArtifactSpec{}
	}
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
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkArtifact(ctx, client, artifacts)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(artifact.Table, *ids), nil
}

func (b *EntBackend) IngestArtifact(ctx context.Context, art *model.IDorArtifactInput) (string, error) {
	id, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		return upsertArtifact(ctx, client, art)
	})
	if txErr != nil {
		return "", txErr
	}
	return toGlobalID(artifact.Table, *id), nil
}

func upsertBulkArtifact(ctx context.Context, tx *ent.Tx, artInputs []*model.IDorArtifactInput) (*[]string, error) {
	batches := chunk(artInputs, MaxBatchSize)
	ids := make([]string, 0)

	for _, artifacts := range batches {
		creates := make([]*ent.ArtifactCreate, len(artifacts))
		for i, art := range artifacts {
			artInput := art
			artifactID := generateUUIDKey([]byte(helpers.GetKey[*model.ArtifactInputSpec, string](artInput.ArtifactInput, helpers.ArtifactServerKey)))
			creates[i] = generateArtifactCreate(tx, &artifactID, artInput)

			ids = append(ids, artifactID.String())
		}

		err := tx.Artifact.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(artifact.FieldDigest),
			).
			DoNothing().
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
	artifactID := generateUUIDKey([]byte(helpers.GetKey[*model.ArtifactInputSpec, string](art.ArtifactInput, helpers.ArtifactServerKey)))
	insert := generateArtifactCreate(tx, &artifactID, art)
	err := insert.
		OnConflict(
			sql.ConflictColumns(artifact.FieldDigest),
		).
		DoNothing().
		Exec(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert artifact")
		}
	}
	return ptrfrom.String(artifactID.String()), nil
}

func (b *EntBackend) artifactNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.Artifact.Query().
		Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeArtifactHashEqual] {
		query.
			WithHashEqualArtA(func(q *ent.HashEqualQuery) {
				getHashEqualObject(q)
			}).
			WithHashEqualArtB(func(q *ent.HashEqualQuery) {
				getHashEqualObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactIsOccurrence] {
		query.
			WithOccurrences(func(q *ent.OccurrenceQuery) {
				getOccurrenceObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactHasSbom] {
		query.
			WithSbom(func(q *ent.BillOfMaterialsQuery) {
				getSBOMObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactHasSlsa] {
		query.
			WithAttestations(func(q *ent.SLSAAttestationQuery) {
				getSLSAObject(q)
			}).
			WithAttestationsSubject(func(q *ent.SLSAAttestationQuery) {
				getSLSAObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactCertifyVexStatement] {
		query.
			WithVex(func(q *ent.CertifyVexQuery) {
				getVEXObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactCertifyBad] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeBAD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactCertifyGood] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeGOOD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactHasMetadata] {
		query.
			WithMetadata(func(q *ent.HasMetadataQuery) {
				getHasMetadataObject(q)
			})
	}
	if allowedEdges[model.EdgeArtifactPointOfContact] {
		query.
			WithPoc(func(q *ent.PointOfContactQuery) {
				getPointOfContactObject(q)
			})
	}

	query.
		Limit(MaxPageSize)

	artifacts, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed query artifact with node ID: %s with error: %w", nodeID, err)
	}

	for _, foundArt := range artifacts {
		for _, hashEqualA := range foundArt.Edges.HashEqualArtA {
			out = append(out, toModelHashEqual(hashEqualA))
		}
		for _, hashEqualB := range foundArt.Edges.HashEqualArtB {
			out = append(out, toModelHashEqual(hashEqualB))
		}
		for _, foundOccur := range foundArt.Edges.Occurrences {
			out = append(out, toModelIsOccurrenceWithSubject(foundOccur))
		}
		for _, foundSBOM := range foundArt.Edges.Sbom {
			out = append(out, toModelHasSBOM(foundSBOM))
		}
		for _, foundSLSA := range foundArt.Edges.Attestations {
			out = append(out, toModelHasSLSA(foundSLSA))
		}
		for _, foundSLSA := range foundArt.Edges.AttestationsSubject {
			out = append(out, toModelHasSLSA(foundSLSA))
		}
		for _, foundVex := range foundArt.Edges.Vex {
			out = append(out, toModelCertifyVEXStatement(foundVex))
		}
		for _, foundCert := range foundArt.Edges.Certification {
			if foundCert.Type == certification.TypeBAD {
				out = append(out, toModelCertifyBad(foundCert))
			}
			if foundCert.Type == certification.TypeGOOD {
				out = append(out, toModelCertifyGood(foundCert))
			}
		}
		for _, foundMeta := range foundArt.Edges.Metadata {
			out = append(out, toModelHasMetadata(foundMeta))
		}
		for _, foundPOC := range foundArt.Edges.Poc {
			out = append(out, toModelPointOfContact(foundPOC))
		}
	}

	return out, nil
}
