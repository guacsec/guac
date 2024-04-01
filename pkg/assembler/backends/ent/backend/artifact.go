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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pointofcontact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
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

func (b *EntBackend) artifactNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}
	if allowedEdges[model.EdgeArtifactHashEqual] {
		// hashEqualSubjectArtEdgesStr collection query
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithHashEqualArtA().
			WithHashEqualArtB().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			hashEqualAs, err := foundArt.HashEqualArtA(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get hashEqual neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, hashEqualA := range hashEqualAs {
				out = append(out, toGlobalID(hashequal.Table, hashEqualA.ID.String()))
			}
			hashEqualBs, err := foundArt.HashEqualArtB(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get hashEqual neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, hashEqualB := range hashEqualBs {
				out = append(out, toGlobalID(hashequal.Table, hashEqualB.ID.String()))
			}
		}
	}
	if allowedEdges[model.EdgeArtifactIsOccurrence] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithOccurrences().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			occurs, err := foundArt.Occurrences(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get occurrence neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundOccur := range occurs {
				out = append(out, toGlobalID(occurrence.Table, foundOccur.ID.String()))
			}
		}
	}
	if allowedEdges[model.EdgeArtifactHasSbom] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithSbom().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			sboms, err := foundArt.Sbom(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get hasSBOM neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundSBOM := range sboms {
				out = append(out, toGlobalID(billofmaterials.Table, foundSBOM.ID.String()))
			}
		}
	}
	if allowedEdges[model.EdgeArtifactHasSlsa] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithAttestations().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			slsas, err := foundArt.Attestations(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get hasSLSA neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundSLSA := range slsas {
				out = append(out, toGlobalID(slsaattestation.Table, foundSLSA.ID.String()))
			}
		}
	}
	if allowedEdges[model.EdgeArtifactCertifyVexStatement] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithVex().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			vexs, err := foundArt.Vex(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get VEX neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundVex := range vexs {
				out = append(out, toGlobalID(certifyvex.Table, foundVex.ID.String()))
			}
		}
	}
	if allowedEdges[model.EdgeArtifactCertifyBad] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithCertification().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			certs, err := foundArt.Certification(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get certifyBad neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundCert := range certs {
				if foundCert.Type == certification.TypeBAD {
					out = append(out, toGlobalID(certification.Table, foundCert.ID.String()))
				}
			}
		}
	}
	if allowedEdges[model.EdgeArtifactCertifyGood] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithCertification().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			certs, err := foundArt.Certification(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get certifyGood neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundCert := range certs {
				if foundCert.Type == certification.TypeGOOD {
					out = append(out, toGlobalID(certification.Table, foundCert.ID.String()))
				}
			}
		}
	}
	if allowedEdges[model.EdgeArtifactHasMetadata] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithMetadata().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			metas, err := foundArt.Metadata(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get hasMetadata neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundMeta := range metas {
				out = append(out, toGlobalID(hasmetadata.Table, foundMeta.ID.String()))
			}
		}
	}
	if allowedEdges[model.EdgeArtifactPointOfContact] {
		query := b.client.Artifact.Query().
			Where(artifactQueryPredicates(&model.ArtifactSpec{ID: &nodeID})).
			WithPoc().
			Limit(MaxPageSize)

		artifacts, err := query.All(ctx)
		if err != nil {
			return nil, err
		}

		for _, foundArt := range artifacts {
			pocs, err := foundArt.Poc(ctx)
			if err != nil {
				return []string{}, fmt.Errorf("failed to get point of contact neighbors for node ID: %s with error: %w", nodeID, err)
			}
			for _, foundPOC := range pocs {
				out = append(out, toGlobalID(pointofcontact.Table, foundPOC.ID.String()))
			}
		}
	}

	return out, nil
}
