//
// Copyright 2022 The GUAC Authors.
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
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	cosign_remote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"golang.org/x/sync/errgroup"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
)

const (
	OCICollector = "OCICollector"
)

// OCI artifact types
const (
	// used by referrer sboms
	TextSpdxJson = "text/spdx+json"
	// used by cosign sboms
	SpdxJson = "spdx+json"
	//InTotoJson       = "application/vnd.in-toto+json"
	DsseEnvelopeJson = "application/vnd.dsse.envelope.v1+json"
)

// wellKnownOCIArtifactTypes is a map of OCI media types to document type and format
// document and format is returned as a tuple
var wellKnownOCIArtifactTypes = map[string]struct {
	documentType processor.DocumentType
	formatType   processor.FormatType
}{
	TextSpdxJson: {
		documentType: processor.DocumentSPDX,
		formatType:   processor.FormatJSON,
	},
	SpdxJson: {
		documentType: processor.DocumentSPDX,
		formatType:   processor.FormatJSON,
	},
	//InTotoJson: {
	//	documentType: processor.DocumentITE6Generic,
	//	formatType:   processor.FormatJSON,
	//},
	DsseEnvelopeJson: {
		documentType: processor.DocumentDSSE,
		formatType:   processor.FormatJSON,
	},
}

type ociCollector struct {
	collectDataSource datasource.CollectSource
	checkedDigest     sync.Map
	poll              bool
	interval          time.Duration
}

var collectors = map[string]Collector{}

// NewOCICollector initializes the oci collector by passing in the repo and tag being collected.
// Note: OCI collector can be called upon by a upstream registry collector in the future to collect from all
// repos in a given registry. For further details see issue #298
//
// Interval should be set to about 5 mins or more for production so that it doesn't clobber registries.
func NewOCICollector(ctx context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration) *ociCollector {
	return &ociCollector{
		collectDataSource: collectDataSource,
		checkedDigest:     sync.Map{},
		poll:              poll,
		interval:          interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	repoRefs := map[string][]name.Reference{}

	retrieverFunc := func() error {
		if err := o.populateRepoTags(ctx, repoRefs); err != nil {
			return fmt.Errorf("unable to populate repotags: %w", err)
		}
		for repo, refs := range repoRefs {
			// when polling if tags are specified, it will never get any new tags
			// that might be added after the fact. Defeating the point of the polling
			if len(refs) > 0 && o.poll {
				return errors.New("image tag should not specified when using polling")
			}
			repo, err := name.NewRepository(repo)
			if err != nil {
				return err
			}

			if len(refs) == 0 {
				refs, err = o.getTags(ctx, repo)
				if err != nil {
					return err
				}
			}

			return o.fetch(ctx, refs, docChannel)

		}
		return nil
	}

	if o.poll {
		for {
			if err := retrieverFunc(); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.interval):
			}
		}
	}
	return retrieverFunc()
}

func (o *ociCollector) populateRepoTags(ctx context.Context, repoRefs map[string][]name.Reference) error {
	logger := logging.FromContext(ctx)
	ds, err := o.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, d := range ds.OciDataSources {
		imageRef, err := name.ParseReference(d.Value)
		if err != nil {
			logger.Errorf("unable to parse OCI path: %v", d.Value)
			continue
		}

		var repositoryName string
		switch ref := imageRef.(type) {
		case name.Tag:
			repositoryName = ref.Repository.String()
		case name.Digest:
			repositoryName = ref.Repository.String()
		}

		// If an image reference has no tag or is a digest, then it is considered as getting all tags
		if isRepositoryReference(imageRef) {
			repoRefs[repositoryName] = []name.Reference{}
		} else {
			// if the list is equal to the empty list, it is already looking for
			// all tags
			if repoRefs[repositoryName] == nil || len(repoRefs[repositoryName]) > 0 {
				repoRefs[repositoryName] = append(repoRefs[repositoryName], imageRef)
			}

		}
	}
	return nil
}

func (o *ociCollector) fetch(ctx context.Context, refs []name.Reference, docChannel chan<- *processor.Document) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, r := range refs {
		r := r
		digest, err := cosign_remote.ResolveDigest(r, cosign_remote.WithRemoteOptions(remoteDefaultOpts(ctx)...))
		if err != nil {
			return err
		}
		if !o.isDigestCollected(digest.Context(), digest) {
			g.Go(func() error {
				return o.fetchOCIArtifacts(ctx, digest, docChannel)
			})
		}
	}
	return g.Wait()
}

func (o *ociCollector) getTags(ctx context.Context, repo name.Repository) ([]name.Reference, error) {
	tags, err := remote.List(repo, remoteDefaultOpts(ctx)...)
	if err != nil {
		return nil, err
	}

	tagRefs := make([]name.Reference, 0, len(tags))

	for _, tag := range tags {
		if !strings.HasSuffix(tag, "sbom") && !strings.HasSuffix(tag, "att") && !strings.HasSuffix(tag, "sig") {
			tagRefs = append(tagRefs, repo.Tag(tag))
		}
	}
	return tagRefs, nil
}

// Note: fetchOCIArtifacts currently does not re-check if a new sbom or attestation get reuploaded during polling with the same image digest.
// A workaround for this would be to run the collector again with a specific tag without polling and ingest like normal
func (o *ociCollector) fetchOCIArtifacts(ctx context.Context, digest name.Digest, docChannel chan<- *processor.Document) error {
	defaultOpts := remoteDefaultOpts(ctx)

	signedEntity, err := cosign_remote.SignedEntity(digest, cosign_remote.WithRemoteOptions(defaultOpts...))
	if err != nil {
		return fmt.Errorf("failed retrieving manifest head: %w", err)
	}

	var collectErr error

	switch signed := signedEntity.(type) {
	case oci.SignedImage:
		collectErr = errors.Join(collectErr, collect(ctx, digest, docChannel, defaultOpts...))
		o.markDigestAsCollected(digest.Context(), digest)
	case oci.SignedImageIndex:
		collectErr = errors.Join(collectErr, collect(ctx, digest, docChannel, defaultOpts...))
		o.markDigestAsCollected(digest.Context(), digest)

		// collect manifests of index
		indexManifest, err := signed.IndexManifest()
		if err != nil {
			return err
		}
		for _, m := range indexManifest.Manifests {
			manifestRef := digest.Context().Digest(m.Digest.String())
			manifestRemoteOpts := remoteDefaultOpts(ctx)
			if m.Platform != nil {
				manifestRemoteOpts = append(manifestRemoteOpts, remote.WithPlatform(*m.Platform))
			}
			collectErr = errors.Join(collectErr, collect(ctx, manifestRef, docChannel, manifestRemoteOpts...))
			o.markDigestAsCollected(manifestRef.Repository, manifestRef)
		}
	}
	return collectErr
}

// Type is the collector type of the collector
func (o *ociCollector) Type() string {
	return OCICollector
}

// markDigestAsCollected adds the given digest to the list of collected digests for the given repository.
// If the repository is not yet in the checkedDigest map, it will be added with an empty slice of digests.
func (o *ociCollector) markDigestAsCollected(repo name.Repository, digest name.Digest) {
	collectedDigests, ok := o.checkedDigest.Load(repo)
	if !ok {
		o.checkedDigest.Store(repo, []name.Digest{})
	}
	digests, ok := collectedDigests.([]name.Digest)
	if !ok {
		return
	}
	o.checkedDigest.Store(repo, append(digests, digest))
}

// isDigestCollected checks if a given digest has already been collected for a given repository.
// It returns true if the digest has been collected, false otherwise.
func (o *ociCollector) isDigestCollected(repo name.Repository, digest name.Digest) bool {
	collectedDigests, ok := o.checkedDigest.Load(repo)
	if !ok {
		o.checkedDigest.Store(repo, []name.Digest{})
		return false
	} else {
		digests, ok := collectedDigests.([]name.Digest)
		if !ok {
			return false
		}
		return slices.Contains(digests, digest)
	}
}

// isRepositoryReference determines if an OCI reference referes to a specific image or repository
func isRepositoryReference(r name.Reference) bool {
	// the reference parsing automatically sets the tag to latest if there is no tag
	// specified, thus we need to check the reference to see if the latest tag was actually
	// included.
	switch ref := r.(type) {
	case name.Tag:
		{
			return ref.TagStr() == name.DefaultTag && !strings.HasSuffix(ref.String(), name.DefaultTag)
		}
		// if reference is parsed as a digest, there is always a specific hash specified
	case name.Digest:
		return false
	}
	return false
}

func remoteDefaultOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithUserAgent(version.UserAgent),
		remote.WithContext(ctx),
	}
}
