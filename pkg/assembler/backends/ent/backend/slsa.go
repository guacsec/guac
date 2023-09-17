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
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) HasSlsa(ctx context.Context, spec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	query := []predicate.SLSAAttestation{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.BuildType, slsaattestation.BuildTypeEQ),
		optionalPredicate(spec.SlsaVersion, slsaattestation.SlsaVersionEQ),
		optionalPredicate(spec.Collector, slsaattestation.CollectorEQ),
		optionalPredicate(spec.Origin, slsaattestation.OriginEQ),
		optionalPredicate(spec.FinishedOn, slsaattestation.FinishedOnEQ),
		optionalPredicate(spec.StartedOn, slsaattestation.StartedOnEQ),
	}

	if spec.BuiltBy != nil {
		query = append(query, slsaattestation.HasBuiltByWith(builderQueryPredicate(spec.BuiltBy)))
	}

	if spec.Subject != nil {
		query = append(query, slsaattestation.HasSubjectWith(artifactQueryPredicates(spec.Subject)))
	}

	for _, art := range spec.BuiltFrom {
		query = append(query, slsaattestation.HasBuiltFromWith(artifactQueryPredicates(art)))
	}

	records, err := b.client.SLSAAttestation.Query().
		Where(query...).
		WithSubject().
		WithBuiltBy().
		WithBuiltFrom().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelHasSLSA), nil
}

func (b *EntBackend) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	att, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SLSAAttestation, error) {
		return upsertSLSA(ctx, ent.TxFromContext(ctx), subject, builtFrom, builtBy, slsa)
	})
	if err != nil {
		return nil, err
	}

	return toModelHasSLSA(att), nil
}

func (b *EntBackend) IngestSLSAs(ctx context.Context, subjects []*model.ArtifactInputSpec, builtFromList [][]*model.ArtifactInputSpec, builtByList []*model.BuilderInputSpec, slsaList []*model.SLSAInputSpec) ([]*model.HasSlsa, error) {
	var modelHasSlsas []*model.HasSlsa
	for i, slsa := range slsaList {
		modelHasSlsa, err := b.IngestSLSA(ctx, *subjects[i], builtFromList[i], *builtByList[i], *slsa)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSLSAs failed with err: %v", err)
		}
		modelHasSlsas = append(modelHasSlsas, modelHasSlsa)
	}
	return modelHasSlsas, nil
}

func upsertSLSA(ctx context.Context, client *ent.Tx, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*ent.SLSAAttestation, error) {
	builder, err := client.Builder.Query().Where(builderInputQueryPredicate(builtBy)).Only(ctx)
	if err != nil {
		return nil, err
	}

	// artifacts, err := ingestArtifacts(ctx, client.Client(), builtFrom)
	artifacts, err := client.Artifact.Query().Where(
		artifact.Or(collect(fromPtrSlice(builtFrom), artifactQueryInputPredicates)...),
	).All(ctx)
	if err != nil {
		return nil, err
	}

	if len(artifacts) == 0 {
		return nil, fmt.Errorf("no artifacts found for builtFrom")
	}

	subjectArtifact, err := client.Artifact.Query().Where(artifactQueryInputPredicates(subject)).Only(ctx)
	if err != nil {
		return nil, err
	}

	id, err := client.SLSAAttestation.Create().
		SetBuiltFromHash(hashBuiltFromVersion(artifacts)).
		SetSubject(subjectArtifact).
		SetBuildType(slsa.BuildType).
		SetBuiltBy(builder).
		SetCollector(slsa.Collector).
		SetOrigin(slsa.Origin).
		SetSlsaVersion(slsa.SlsaVersion).
		SetSlsaPredicate(toSLSAInputPredicate(slsa.SlsaPredicate)).
		SetNillableStartedOn(slsa.StartedOn).
		SetNillableFinishedOn(slsa.FinishedOn).
		AddBuiltFrom(artifacts...).
		OnConflict(
			sql.ConflictColumns(
				slsaattestation.FieldSubjectID,
				slsaattestation.FieldOrigin,
				slsaattestation.FieldCollector,
				slsaattestation.FieldBuildType,
				slsaattestation.FieldSlsaVersion,
				slsaattestation.FieldBuiltByID,
				slsaattestation.FieldBuiltFromHash,
			),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.SLSAAttestation.Query().
		Where(slsaattestation.IDEQ(id)).
		WithBuiltBy().
		WithBuiltFrom().
		WithSubject().
		Only(ctx)
}

func toSLSAInputPredicate(rows []*model.SLSAPredicateInputSpec) []*model.SLSAPredicate {
	if len(rows) > 0 {
		preds := make([]*model.SLSAPredicate, len(rows))
		for i, row := range rows {
			preds[i] = &model.SLSAPredicate{
				Key:   row.Key,
				Value: row.Value,
			}
		}

		return preds
	} else {
		return nil
	}
}

func toModelHasSLSA(att *ent.SLSAAttestation) *model.HasSlsa {
	return &model.HasSlsa{
		ID:      nodeID(att.ID),
		Subject: toModelArtifact(att.Edges.Subject),
		Slsa: &model.Slsa{
			BuiltFrom:     collect(att.Edges.BuiltFrom, toModelArtifact),
			BuiltBy:       toModelBuilder(att.Edges.BuiltBy),
			BuildType:     att.BuildType,
			SlsaPredicate: att.SlsaPredicate,
			SlsaVersion:   att.SlsaVersion,
			StartedOn:     att.StartedOn,
			FinishedOn:    att.FinishedOn,
			Origin:        att.Origin,
			Collector:     att.Collector,
		},
	}
}

func hashBuiltFromVersion(builtFrom []*ent.Artifact) string {
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	sort.Slice(builtFrom, func(i, j int) bool { return builtFrom[i].Digest < builtFrom[j].Digest })

	for _, v := range builtFrom {
		content.WriteString(v.Digest)
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}
