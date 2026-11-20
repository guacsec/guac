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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	sa "github.com/guacsec/guac/pkg/assembler/backends/ent/safetyassertion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	packageurl "github.com/package-url/packageurl-go"
)

var errSafetyReconciliationConflict = errors.New("safety assertion changed during reconciliation")
var errInvalidSafetyIdentity = errors.New("invalid or unsupported safety target identity")

// ReconcileSafetyAssertion derives bindings exclusively from stored declarations
// and graph identities. Optimistic concurrency prevents a slower evaluation from
// replacing the result of another certifier run. The external decision is immutable.
func (b *EntBackend) ReconcileSafetyAssertion(ctx context.Context, value string) (*model.SafetyAssertion, error) {
	id, err := safetyAssertionID(value)
	if err != nil {
		return nil, err
	}
	for range 10 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := WithinTX(ctx, b.client, func(ctx context.Context) (*model.SafetyAssertion, error) {
			tx := ent.TxFromContext(ctx)
			row, err := tx.SafetyAssertion.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			now := time.Now().UTC()
			status, reason, product, component, err := resolveSafetyTarget(ctx, tx, row, now)
			if err != nil {
				return nil, err
			}
			update := tx.SafetyAssertion.Update().Where(sa.ID(id), sa.CorrelationRevision(row.CorrelationRevision)).
				SetCorrelationStatus(status).SetCorrelationReason(reason).SetLastEvaluatedAt(now).AddCorrelationRevision(1)
			if status == sa.CorrelationStatusMATCHED {
				matchedBy := "EXACT_VERSIONED_PURL"
				if row.ComponentDigest != nil {
					matchedBy += "+COMPONENT_DIGEST"
				}
				resolvedAt := now
				if row.ResolvedAt != nil && row.ResolvedProductID != nil && row.ResolvedComponentID != nil && *row.ResolvedProductID == product.ID && *row.ResolvedComponentID == component.ID {
					resolvedAt = *row.ResolvedAt
				}
				update.SetResolvedProductID(product.ID).SetResolvedComponentID(component.ID).SetMatchedBy(matchedBy).SetResolvedAt(resolvedAt)
			} else {
				update.ClearResolvedProductID().ClearResolvedComponentID().ClearMatchedBy().ClearResolvedAt()
			}
			n, err := update.Save(ctx)
			if err != nil {
				return nil, err
			}
			if n != 1 {
				return nil, errSafetyReconciliationConflict
			}
			resolved, err := safetyAssertionObjects(tx.SafetyAssertion.Query()).Where(sa.ID(id)).Only(ctx)
			if err != nil {
				return nil, err
			}
			return toModelSafetyAssertion(resolved), nil
		})
		if errors.Is(err, errSafetyReconciliationConflict) {
			continue
		}
		return result, err
	}
	return nil, errSafetyReconciliationConflict
}

func resolveSafetyTarget(ctx context.Context, tx *ent.Tx, row *ent.SafetyAssertion, now time.Time) (sa.CorrelationStatus, string, *ent.PackageVersion, *ent.PackageVersion, error) {
	if row.ValidUntil != nil && !row.ValidUntil.After(now) {
		return sa.CorrelationStatusSTALE, "ASSERTION_EXPIRED", nil, nil, nil
	}
	products, err := safetyPackageCandidates(ctx, tx, row.ProductPurl)
	if errors.Is(err, errInvalidSafetyIdentity) {
		return sa.CorrelationStatusINVALID, "INVALID_PRODUCT_IDENTITY", nil, nil, nil
	}
	if err != nil {
		return "", "", nil, nil, err
	}
	components, err := safetyPackageCandidates(ctx, tx, row.ComponentPurl)
	if errors.Is(err, errInvalidSafetyIdentity) {
		return sa.CorrelationStatusINVALID, "INVALID_COMPONENT_IDENTITY", nil, nil, nil
	}
	if err != nil {
		return "", "", nil, nil, err
	}
	if len(products) > 1 || len(components) > 1 {
		return sa.CorrelationStatusAMBIGUOUS, "MULTIPLE_EXACT_PACKAGE_VERSIONS", nil, nil, nil
	}
	if len(products) == 0 && len(components) == 0 {
		return sa.CorrelationStatusPENDING, "PRODUCT_AND_COMPONENT_NOT_FOUND", nil, nil, nil
	}
	if len(products) == 0 {
		return sa.CorrelationStatusPENDING, "PRODUCT_NOT_FOUND", nil, nil, nil
	}
	if len(components) == 0 {
		return sa.CorrelationStatusPENDING, "COMPONENT_NOT_FOUND", nil, nil, nil
	}
	if row.ComponentDigest != nil {
		if row.ComponentDigestAlgorithm == nil {
			return sa.CorrelationStatusINVALID, "INCOMPLETE_COMPONENT_DIGEST", nil, nil, nil
		}
		occurrences, err := tx.Occurrence.Query().Where(occurrence.PackageID(components[0].ID)).WithArtifact().All(ctx)
		if err != nil {
			return "", "", nil, nil, err
		}
		observed := false
		for _, occurrence := range occurrences {
			artifact := occurrence.Edges.Artifact
			if artifact == nil {
				continue
			}
			algorithm := strings.ToLower(artifact.Algorithm)
			// CycloneDX hashes retain the standard hyphenated SHA names in
			// GUAC artifacts, while the assertion contract uses compact names.
			switch algorithm {
			case "sha-256":
				algorithm = "sha256"
			case "sha-384":
				algorithm = "sha384"
			case "sha-512":
				algorithm = "sha512"
			}
			if algorithm != *row.ComponentDigestAlgorithm {
				continue
			}
			observed = true
			if !strings.EqualFold(artifact.Digest, *row.ComponentDigest) {
				return sa.CorrelationStatusINVALID, "COMPONENT_DIGEST_MISMATCH", nil, nil, nil
			}
		}
		// Absence of a digest is not evidence of a mismatch, or of a match.
		if !observed {
			return sa.CorrelationStatusPENDING, "COMPONENT_DIGEST_NOT_OBSERVED", nil, nil, nil
		}
	}
	return sa.CorrelationStatusMATCHED, "EXACT_PACKAGE_VERSIONS_RESOLVED", products[0], components[0], nil
}

func safetyPackageCandidates(ctx context.Context, tx *ent.Tx, value string) ([]*ent.PackageVersion, error) {
	p, err := packageurl.FromString(value)
	if err != nil || p.Version == "" {
		return nil, errInvalidSafetyIdentity
	}
	// Reuse GUAC's carrier conversion, including OCI/Docker repository namespaces.
	converted, err := helpers.PurlToPkg(p.ToString())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSafetyIdentity, err)
	}
	input := model.PkgInputSpec{Type: converted.Type, Namespace: converted.Namespace, Name: converted.Name, Version: converted.Version, Subpath: converted.Subpath}
	for _, q := range converted.Qualifiers {
		input.Qualifiers = append(input.Qualifiers, &model.PackageQualifierInputSpec{Key: q.Key, Value: q.Value})
	}
	// Use the semantic fields, not hashes or package names alone. Limit to two:
	// a second candidate is sufficient to fail closed as ambiguous.
	return tx.PackageVersion.Query().Where(packageVersionInputQuery(input)).WithName().Limit(2).All(ctx)
}
