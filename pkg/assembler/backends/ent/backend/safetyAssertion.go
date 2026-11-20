//
// Copyright 2026 The GUAC Authors.
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
	"errors"
	"fmt"
	"reflect"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	sa "github.com/guacsec/guac/pkg/assembler/backends/ent/safetyassertion"
	sd "github.com/guacsec/guac/pkg/assembler/backends/ent/safetyassertiondocument"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	packageurl "github.com/package-url/packageurl-go"
)

func safetyAssertionID(value string) (uuid.UUID, error) {
	id := fromGlobalID(value)
	if id.nodeType != sa.Table {
		return uuid.Nil, fmt.Errorf("expected a safety assertion ID")
	}
	return uuid.Parse(id.id)
}

func (b *EntBackend) IngestSafetyAssertion(ctx context.Context, input model.SafetyAssertionInputSpec) (string, error) {
	a, hash, err := helper.NormalizeSafetyAssertion(input)
	if err != nil {
		return "", err
	}
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		err := tx.SafetyAssertionDocument.Create().
			SetDigestAlgorithm(a.DocumentDigestAlgorithm).SetDigest(a.DocumentDigest).
			SetDocumentRef(a.DocumentRef).SetOrigin(a.Origin).SetCollector(a.Collector).
			SetNillableSourceAuthority(a.SourceAuthority).
			OnConflict(sql.ConflictColumns(sd.FieldDigestAlgorithm, sd.FieldDigest)).DoNothing().Exec(ctx)
		if err != nil && !errors.Is(err, stdsql.ErrNoRows) {
			return nil, fmt.Errorf("ingest safety assertion document: %w", err)
		}
		document, err := tx.SafetyAssertionDocument.Query().Where(sd.DigestAlgorithm(a.DocumentDigestAlgorithm), sd.Digest(a.DocumentDigest)).Only(ctx)
		if err != nil {
			return nil, err
		}
		// A document identity is immutable. A retry must not silently replace its
		// provenance, including when another assertion from the document is ingested.
		if document.DocumentRef != a.DocumentRef || document.Origin != a.Origin || document.Collector != a.Collector || !reflect.DeepEqual(document.SourceAuthority, a.SourceAuthority) {
			return nil, fmt.Errorf("conflicting provenance for safety assertion document")
		}
		err = tx.SafetyAssertion.Create().SetDocumentID(document.ID).
			SetAssertionID(a.AssertionID).SetContentHash(hash).
			SetSafetyRelevance(sa.SafetyRelevance(a.SafetyRelevance)).
			SetNillableClassificationScheme(a.ClassificationScheme).SetNillableClassificationValue(a.ClassificationValue).
			SetRationale(a.Rationale).SetDecisionStatus(sa.DecisionStatus(a.DecisionStatus)).SetNillableReviewer(a.Reviewer).
			SetAssertedAt(a.AssertedAt).SetNillableValidUntil(a.ValidUntil).
			SetProductPurl(a.ProductPurl).SetComponentPurl(a.ComponentPurl).SetNillableComponentBomRef(a.ComponentBomRef).
			SetNillableComponentDigestAlgorithm(a.ComponentDigestAlgorithm).SetNillableComponentDigest(a.ComponentDigest).
			SetEvidence(a.Evidence).
			OnConflict(sql.ConflictColumns(sa.FieldDocumentID, sa.FieldAssertionID)).DoNothing().Exec(ctx)
		if err != nil && !errors.Is(err, stdsql.ErrNoRows) {
			return nil, fmt.Errorf("ingest safety assertion: %w", err)
		}
		assertion, err := tx.SafetyAssertion.Query().Where(sa.DocumentID(document.ID), sa.AssertionID(a.AssertionID)).Only(ctx)
		if err != nil {
			return nil, err
		}
		if assertion.ContentHash != hash {
			return nil, fmt.Errorf("conflicting content for assertion %q in the same document", a.AssertionID)
		}
		result := toGlobalID(sa.Table, assertion.ID.String())
		return &result, nil
	})
	if err != nil {
		return "", err
	}
	return *id, nil
}

func safetyAssertionPredicates(spec *model.SafetyAssertionSpec) ([]predicate.SafetyAssertion, error) {
	if spec == nil {
		return nil, nil
	}
	p := []predicate.SafetyAssertion{}
	if spec.ID != nil {
		id, err := safetyAssertionID(*spec.ID)
		if err != nil {
			return nil, err
		}
		p = append(p, sa.ID(id))
	}
	if spec.AssertionID != nil {
		p = append(p, sa.AssertionID(*spec.AssertionID))
	}
	for _, v := range []struct {
		value     *string
		predicate func(string) predicate.SafetyAssertion
	}{
		{spec.ProductPurl, sa.ProductPurl}, {spec.ComponentPurl, sa.ComponentPurl},
	} {
		if v.value == nil {
			continue
		}
		parsed, err := packageurl.FromString(*v.value)
		if err != nil || parsed.Version == "" {
			return nil, fmt.Errorf("PURL filters require a complete versioned identity")
		}
		p = append(p, v.predicate(parsed.ToString()))
	}
	if spec.SafetyRelevance != nil {
		if !spec.SafetyRelevance.IsValid() {
			return nil, fmt.Errorf("invalid safety relevance")
		}
		p = append(p, sa.SafetyRelevanceEQ(sa.SafetyRelevance(*spec.SafetyRelevance)))
	}
	if spec.DecisionStatus != nil {
		if !spec.DecisionStatus.IsValid() {
			return nil, fmt.Errorf("invalid decision status")
		}
		p = append(p, sa.DecisionStatusEQ(sa.DecisionStatus(*spec.DecisionStatus)))
	}
	if spec.CorrelationStatus != nil && *spec.CorrelationStatus != model.SafetyCorrelationStatusPending {
		return nil, fmt.Errorf("only PENDING correlation is supported by this implementation")
	}
	if spec.ClassificationScheme != nil {
		p = append(p, sa.ClassificationScheme(*spec.ClassificationScheme))
	}
	if spec.ClassificationValue != nil {
		p = append(p, sa.ClassificationValue(*spec.ClassificationValue))
	}
	d := []predicate.SafetyAssertionDocument{}
	if spec.SourceAuthority != nil {
		d = append(d, sd.SourceAuthority(*spec.SourceAuthority))
	}
	if spec.Origin != nil {
		d = append(d, sd.Origin(*spec.Origin))
	}
	if spec.DocumentDigestAlgorithm != nil {
		d = append(d, sd.DigestAlgorithm(strings.ToLower(*spec.DocumentDigestAlgorithm)))
	}
	if spec.DocumentDigest != nil {
		d = append(d, sd.Digest(strings.ToLower(*spec.DocumentDigest)))
	}
	if len(d) > 0 {
		p = append(p, sa.HasDocumentWith(d...))
	}
	return p, nil
}

func (b *EntBackend) SafetyAssertions(ctx context.Context, spec *model.SafetyAssertionSpec) ([]*model.SafetyAssertion, error) {
	p, err := safetyAssertionPredicates(spec)
	if err != nil {
		return nil, err
	}
	rows, err := b.client.SafetyAssertion.Query().Where(p...).WithDocument().Order(ent.Asc(sa.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]*model.SafetyAssertion, 0, len(rows))
	for _, row := range rows {
		results = append(results, toModelSafetyAssertion(row))
	}
	return results, nil
}

func (b *EntBackend) SafetyAssertionList(ctx context.Context, spec model.SafetyAssertionSpec, after *string, first *int) (*model.SafetyAssertionConnection, error) {
	if first != nil && *first < 0 {
		return nil, fmt.Errorf("first must be nonnegative")
	}
	var cursor *ent.Cursor
	if after != nil {
		id, err := safetyAssertionID(*after)
		if err != nil {
			return nil, err
		}
		cursor = &ent.Cursor{ID: id}
	}
	p, err := safetyAssertionPredicates(&spec)
	if err != nil {
		return nil, err
	}
	conn, err := b.client.SafetyAssertion.Query().Where(p...).WithDocument().Paginate(ctx, cursor, first, nil, nil)
	if err != nil {
		return nil, err
	}
	result := &model.SafetyAssertionConnection{TotalCount: conn.TotalCount, PageInfo: &model.PageInfo{HasNextPage: conn.PageInfo.HasNextPage}, Edges: []*model.SafetyAssertionEdge{}}
	for _, edge := range conn.Edges {
		result.Edges = append(result.Edges, &model.SafetyAssertionEdge{Cursor: toGlobalID(sa.Table, edge.Cursor.ID.String()), Node: toModelSafetyAssertion(edge.Node)})
	}
	if conn.PageInfo.StartCursor != nil {
		start := toGlobalID(sa.Table, conn.PageInfo.StartCursor.ID.String())
		result.PageInfo.StartCursor = &start
	}
	if conn.PageInfo.EndCursor != nil {
		end := toGlobalID(sa.Table, conn.PageInfo.EndCursor.ID.String())
		result.PageInfo.EndCursor = &end
	}
	return result, nil
}

func toModelSafetyAssertion(row *ent.SafetyAssertion) *model.SafetyAssertion {
	doc := row.Edges.Document
	evidence := make([]*model.SafetyEvidenceReference, 0, len(row.Evidence))
	for _, e := range row.Evidence {
		evidence = append(evidence, &model.SafetyEvidenceReference{EvidenceID: e.EvidenceID, URI: e.URI, DigestAlgorithm: e.DigestAlgorithm, Digest: e.Digest})
	}
	return &model.SafetyAssertion{
		ID: toGlobalID(sa.Table, row.ID.String()), AssertionID: row.AssertionID,
		SafetyRelevance: model.SafetyRelevance(row.SafetyRelevance), ClassificationScheme: row.ClassificationScheme, ClassificationValue: row.ClassificationValue,
		Rationale: row.Rationale, DecisionStatus: model.SafetyDecisionStatus(row.DecisionStatus), Reviewer: row.Reviewer, AssertedAt: row.AssertedAt, ValidUntil: row.ValidUntil,
		Target: &model.SafetyAssertionTarget{ProductPurl: row.ProductPurl, ComponentPurl: row.ComponentPurl, ComponentBomRef: row.ComponentBomRef,
			ComponentDigestAlgorithm: row.ComponentDigestAlgorithm, ComponentDigest: row.ComponentDigest, CorrelationStatus: model.SafetyCorrelationStatusPending},
		Evidence: evidence, SourceAuthority: doc.SourceAuthority, Origin: doc.Origin, Collector: doc.Collector, DocumentRef: doc.DocumentRef,
		DocumentDigestAlgorithm: doc.DigestAlgorithm, DocumentDigest: doc.Digest,
	}
}
