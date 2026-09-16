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

package oci

import (
	"context"
	"errors"
	"testing"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
)

type manifestGetResult struct {
	manifest manifest.Manifest
	err      error
}

type sequenceManifestGetter struct {
	results []manifestGetResult
	calls   int
}

func (g *sequenceManifestGetter) ManifestGet(context.Context, ref.Ref, ...regclient.ManifestOpts) (manifest.Manifest, error) {
	result := g.results[g.calls]
	g.calls++
	return result.manifest, result.err
}

func TestGetManifestWithRetryRetriesTransientNotFound(t *testing.T) {
	getter := &sequenceManifestGetter{results: []manifestGetResult{
		{err: errs.ErrNotFound},
		{},
	}}
	ctx := logging.WithLogger(context.Background())

	_, err := getManifestWithRetry(ctx, getter, ref.Ref{}, "example@sha256:digest")

	if err != nil {
		t.Fatalf("getManifestWithRetry() error = %v", err)
	}
	if getter.calls != 2 {
		t.Fatalf("ManifestGet() calls = %d, want 2", getter.calls)
	}
}

func TestGetManifestWithRetryReturnsPersistentNotFound(t *testing.T) {
	getter := &sequenceManifestGetter{results: []manifestGetResult{
		{err: errs.ErrNotFound},
		{err: errs.ErrNotFound},
		{err: errs.ErrNotFound},
	}}
	ctx := logging.WithLogger(context.Background())

	_, err := getManifestWithRetry(ctx, getter, ref.Ref{}, "example@sha256:digest")

	if !errors.Is(err, errs.ErrNotFound) {
		t.Fatalf("getManifestWithRetry() error = %v, want ErrNotFound", err)
	}
	if getter.calls != manifestGetAttempts {
		t.Fatalf("ManifestGet() calls = %d, want %d", getter.calls, manifestGetAttempts)
	}
}
