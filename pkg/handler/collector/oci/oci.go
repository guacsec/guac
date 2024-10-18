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
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"
)

const (
	OCICollector = "OCICollector"
)

// OCI artifact types
const (
	SpdxJson   = "application/spdx+json"
	InTotoJson = "application/vnd.in-toto+json"
)

// wellKnownOCIArtifactTypes is a map of OCI media types to document type and format
// document and format is returned as a tuple
var wellKnownOCIArtifactTypes = map[string]struct {
	documentType processor.DocumentType
	formatType   processor.FormatType
}{
	SpdxJson: {
		documentType: processor.DocumentSPDX,
		formatType:   processor.FormatJSON,
	},
	InTotoJson: {
		documentType: processor.DocumentITE6SLSA,
		formatType:   processor.FormatJSON,
	},
}

// wellKnownSuffixes are the well known suffixes for fallback artifacts
var wellKnownSuffixes = []string{"att", "sbom"}

type ociCollector struct {
	collectDataSource datasource.CollectSource
	checkedDigest     sync.Map
	poll              bool
	interval          time.Duration
	// rcOpts are the regclient options
	rcOpts []regclient.Opt
}

// NewOCICollector initializes the oci collector by passing in the repo and tag being collected.
// Note: OCI collector can be called upon by a upstream registry collector in the future to collect from all
// repos in a given registry. For further details see issue #298
//
// Interval should be set to about 5 mins or more for production so that it doesn't clobber registries.
func NewOCICollector(ctx context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration, rcOpts ...regclient.Opt) *ociCollector {
	if rcOpts == nil {
		rcOpts = getRegClientOptions()
	}
	return &ociCollector{
		collectDataSource: collectDataSource,
		checkedDigest:     sync.Map{},
		poll:              poll,
		interval:          interval,
		rcOpts:            rcOpts,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	repoRefs := map[string][]ref.Ref{}

	if o.poll {
		for {
			if err := o.populateRepoRefs(ctx, repoRefs); err != nil {
				return fmt.Errorf("unable to populate reporefs: %w", err)
			}
			for repo, imageRefs := range repoRefs {
				// when polling if tags are specified, it will never get any new tags
				// that might be added after the fact. Defeating the point of the polling
				if len(imageRefs) > 0 {
					return errors.New("image identifiers (tag or digest) should not be specified when using polling")
				}
				if err := o.getRefsAndFetch(ctx, repo, imageRefs, docChannel); err != nil {
					return err
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.interval):
			}
		}
	} else {
		if err := o.populateRepoRefs(ctx, repoRefs); err != nil {
			return fmt.Errorf("unable to populate reporefs: %w", err)
		}
		for repo, imageRefs := range repoRefs {
			if err := o.getRefsAndFetch(ctx, repo, imageRefs, docChannel); err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *ociCollector) populateRepoRefs(ctx context.Context, repoRefs map[string][]ref.Ref) error {
	logger := logging.FromContext(ctx)
	ds, err := o.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, d := range ds.OciDataSources {
		imageRef, err := ref.New(d.Value)
		if err != nil {
			logger.Errorf("unable to parse OCI path: %v", d.Value)
			continue
		}
		imagePath := fmt.Sprintf("%s/%s", imageRef.Registry, imageRef.Repository)

		// If an image reference has no identifier (tag or digest), then
		// it is considered as getting all tags
		if hasNoIdentifier(imageRef) {
			repoRefs[imagePath] = []ref.Ref{}
		} else {
			// if the list is equal to the empty list, it is already looking for
			// all tags
			if repoRefs[imagePath] == nil || len(repoRefs[imagePath]) > 0 {
				repoRefs[imagePath] = append(repoRefs[imagePath], imageRef)
			}

		}
	}
	return nil
}

func (o *ociCollector) getRefsAndFetch(ctx context.Context, repo string, imageRefs []ref.Ref, docChannel chan<- *processor.Document) error {
	if len(imageRefs) > 0 {
		for _, r := range imageRefs {
			if hasNoIdentifier(r) {
				return errors.New("image identifier not specified to fetch")
			}

			rc := regclient.New(o.rcOpts...)
			defer rc.Close(ctx, r)

			if err := o.fetchOCIArtifacts(ctx, repo, rc, r, docChannel); err != nil {
				return err
			}
		}
	} else {
		r, err := ref.New(repo)
		if err != nil {
			return err
		}

		rc := regclient.New(o.rcOpts...)
		defer rc.Close(ctx, r)

		tags, err := rc.TagList(ctx, r)
		if err != nil {
			return fmt.Errorf("reading tags for %s: %w", repo, err)
		}

		for _, tag := range tags.Tags {
			if !strings.HasSuffix(tag, "sbom") && !strings.HasSuffix(tag, "att") && !strings.HasSuffix(tag, "sig") {
				imageTag := fmt.Sprintf("%v:%v", repo, tag)
				r, err := ref.New(imageTag)
				if err != nil {
					return err
				}
				if err := o.fetchOCIArtifacts(ctx, repo, rc, r, docChannel); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Note: fetchOCIArtifacts currently does not re-check if a new sbom or attestation get reuploaded during polling with the same image digest.
// A workaround for this would be to run the collector again with a specific tag without polling and ingest like normal
func (o *ociCollector) fetchOCIArtifacts(ctx context.Context, repo string, rc *regclient.RegClient, image ref.Ref, docChannel chan<- *processor.Document) error {
	// attempt to request only the headers, avoids Docker Hub rate limits
	m, err := rc.ManifestHead(ctx, image)
	if err != nil {
		return fmt.Errorf("failed retrieving manifest head: %w", err)
	}

	// check if the manifest is a manifest list
	if m.IsList() {
		if err := o.fetchManifestList(ctx, repo, rc, image, docChannel); err != nil {
			return err
		}
	}

	// check for fallback artifacts
	if err := o.fetchFallbackArtifacts(ctx, repo, rc, image, m, docChannel); err != nil {
		return err
	}

	// check for referrer artifacts
	if err := o.fetchReferrerArtifacts(ctx, repo, rc, image, docChannel); err != nil {
		return err
	}

	return nil
}

// fetchManifestList fetches the manifest list for the given image and fetches all the platform manifests in parallel.
// It then fetches the artifacts for each platform and sends them to the docChannel.
// It returns an error if any error occurs during the process.
func (o *ociCollector) fetchManifestList(ctx context.Context, repo string, rc *regclient.RegClient, image ref.Ref, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	m, err := rc.ManifestGet(ctx, image)
	if err != nil {
		return fmt.Errorf("failed retrieving manifest: %w", err)
	}

	pl, err := manifest.GetPlatformList(m)
	if err != nil {
		return fmt.Errorf("failed retrieving manifest list: %w", err)
	}

	logger.Infof("%s is manifest list with %d platforms", image.Reference, len(pl))

	// Use goroutines to fetch platforms concurrently
	// Create a channel to collect errors from goroutines
	errorChan := make(chan error, len(pl))
	var wg sync.WaitGroup

	// Create a context with cancel to cancel all goroutines if one of them returns an error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, p := range pl {
		// Increment the WaitGroup counter
		wg.Add(1)
		go func(p *platform.Platform) {
			defer wg.Done() // Decrement the WaitGroup counter when done
			logger.Infof("Fetching platform %s", p)
			desc, err := manifest.GetPlatformDesc(m, p)
			if err != nil {
				errorChan <- fmt.Errorf("failed retrieving platform specific digest: %w", err)
				cancel()
				return
			}
			platformImage := ref.Ref{
				Scheme:     image.Scheme,
				Registry:   image.Registry,
				Repository: image.Repository,
				Digest:     desc.Digest.String(),
			}
			// check if the platform digest has already been collected
			if !o.isDigestCollected(repo, platformImage.Digest) {
				logger.Infof("Fetching %s for platform %s", platformImage.Digest, desc.Platform)
				if err := o.fetchOCIArtifacts(ctx, repo, rc, platformImage, docChannel); err != nil {
					errorChan <- fmt.Errorf("failed fetching artifacts for platform specific digest: %w", err)
					cancel()
				}
				o.markDigestAsCollected(repo, platformImage.Digest)
			}
		}(p)
	}
	// Wait for all goroutines to finish
	wg.Wait()

	// Close the errorChannel to signal that all errors have been collected
	close(errorChan)

	// Check if any errors occurred during processing
	for err := range errorChan {
		if err != nil {
			return err // Return the first error encountered
		}
	}

	return nil
}

// fetchFallbackArtifacts fetches fallback artifacts for the given image manifest and sends them to the docChannel.
// It checks for fallback artifacts by appending well-known suffixes to the image digest and checking if the resulting
// digest+suffix combination has already been collected. If not, it fetches the artifact blobs from the registry and
// marks the digest+suffix combination as collected.
func (o *ociCollector) fetchFallbackArtifacts(ctx context.Context, repo string, rc *regclient.RegClient, image ref.Ref, m manifest.Manifest, docChannel chan<- *processor.Document) error {
	digest := manifest.GetDigest(m)
	image.Digest = digest.String()

	// check for fallback artifacts
	digestFormatted := fmt.Sprintf("%v-%v", digest.Algorithm(), digest.Encoded())
	for _, suffix := range wellKnownSuffixes {
		digestTag := fmt.Sprintf("%v.%v", digestFormatted, suffix)
		// check to see if the digest + suffix has already been collected
		if !o.isDigestCollected(repo, digestTag) {
			imageTag := fmt.Sprintf("%v:%v", repo, digestTag)
			err := fetchOCIArtifactBlobs(ctx, rc, imageTag, "unknown", docChannel)
			if err != nil {
				return fmt.Errorf("failed retrieving artifact blobs from registry fallback artifacts: %w", err)
			}
			o.markDigestAsCollected(repo, digestTag)
		}
	}
	return nil
}

// fetchReferrerArtifacts fetches the referrer artifacts for the given image from the registry using the provided RegClient.
// It fetches the referrers concurrently using goroutines and sends the resulting Document to the provided docChannel.
// It returns an error if any error occurs during the process.
func (o *ociCollector) fetchReferrerArtifacts(ctx context.Context, repo string, rc *regclient.RegClient, image ref.Ref, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	referrerList, err := rc.ReferrerList(ctx, image)
	if err != nil {
		return fmt.Errorf("failed retrieving referrer list: %w", err)
	}

	logger.Infof("Found %d referrers for %s", len(referrerList.Descriptors), image.Digest)

	// Use goroutines to fetch referrers concurrently
	// Create a channel to collect errors from goroutines
	errorChan := make(chan error, len(referrerList.Descriptors))
	var wg sync.WaitGroup

	// Create a context with cancel to cancel all goroutines if one of them returns an error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, referrerDesc := range referrerList.Descriptors {
		// Increment the WaitGroup counter
		wg.Add(1)
		go func(referrerDesc descriptor.Descriptor) {
			defer wg.Done() // Decrement the WaitGroup counter when done
			if _, ok := wellKnownOCIArtifactTypes[referrerDesc.ArtifactType]; ok {
				referrerDescDigest := referrerDesc.Digest.String()

				if !o.isDigestCollected(repo, referrerDescDigest) {
					logger.Infof("Fetching referrer %s with artifact type %s", referrerDescDigest, referrerDesc.ArtifactType)
					referrerDigest := fmt.Sprintf("%v@%v", repo, referrerDescDigest)
					e := fetchOCIArtifactBlobs(ctx, rc, referrerDigest, referrerDesc.ArtifactType, docChannel)
					if e != nil {
						errorChan <- fmt.Errorf("failed retrieving artifact blobs from registry: %w", err)
						cancel()
						return
					}
					o.markDigestAsCollected(repo, referrerDescDigest)
				}
			} else {
				logger.Infof("Skipping referrer %s with unknown artifact type %s", referrerDesc.Digest, referrerDesc.ArtifactType)
			}

		}(referrerDesc)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Close the errorChan to signal that all errors have been collected
	close(errorChan)

	// Check if any errors occurred during processing
	for err := range errorChan {
		if err != nil {
			return err // Return the first error encountered
		}
	}

	return nil
}

// fetchOCIArtifactBlobs fetches the blobs of an OCI artifact and sends them to the provided docChannel.
// It takes a context.Context, a *regclient.RegClient, an artifact string, an artifactType string, and a docChannel chan<- *processor.Document as input.
// Note that we are not concurrently fetching the layers since we will usually have 1 layer per artifact.
// It returns an error if there was an issue fetching the artifact blobs.
func fetchOCIArtifactBlobs(
	ctx context.Context,
	rc *regclient.RegClient,
	artifact,
	artifactType string,
	docChannel chan<- *processor.Document,
) error {
	logger := logging.FromContext(ctx)
	r, err := ref.New(artifact)
	if err != nil {
		return fmt.Errorf("unable to parse OCI reference: %v", artifact)
	}

	m, err := rc.ManifestGet(ctx, r)
	if err != nil {
		// this is a normal behavior, not an error when the digest does not have an attestation
		// explicitly logging it as info to avoid call-stack when logging
		logger.Infof("unable to get manifest for %v: %v", artifact, err)
		return nil
	}

	// go through layers in reverse
	mi, ok := m.(manifest.Imager)
	if !ok {
		return fmt.Errorf("reference is not a known image media type")
	}
	layers, err := mi.GetLayers()
	if err != nil {
		return err
	}
	for i := len(layers) - 1; i >= 0; i-- {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		blob, err := rc.BlobGet(ctx, r, layers[i])
		if err != nil {
			return fmt.Errorf("failed pulling layer %d: %w", i, err)
		}
		btr1, err := blob.RawBody()
		closeErr := blob.Close()
		if err != nil {
			return fmt.Errorf("failed reading layer %d: %w", i, err)
		}
		if closeErr != nil {
			return fmt.Errorf("failed closing layer %d: %w", i, err)
		}

		var docType = processor.DocumentUnknown
		var docFormat = processor.FormatUnknown

		// check if artifactType is in wellKnownOCIArtifactTypes
		if artifactType != "" {
			if wellKnownArtifactType, ok := wellKnownOCIArtifactTypes[artifactType]; ok {
				docType = wellKnownArtifactType.documentType
				docFormat = wellKnownArtifactType.formatType
			}
		}

		doc := &processor.Document{
			Blob:   btr1,
			Type:   docType,
			Format: docFormat,
			SourceInformation: processor.SourceInformation{
				Collector:   string(OCICollector),
				Source:      artifact,
				DocumentRef: events.GetDocRef(btr1),
			},
		}
		docChannel <- doc
	}

	return nil
}

// isDigestCollected checks if a given digest has already been collected for a given repository.
// It returns true if the digest has been collected, false otherwise.
func (o *ociCollector) isDigestCollected(repo string, digest string) bool {
	collectedDigests, ok := o.checkedDigest.Load(repo)
	if !ok {
		o.checkedDigest.Store(repo, []string{})
		return false
	} else {
		digests, ok := collectedDigests.([]string)
		if !ok {
			return false
		}
		return slices.Contains(digests, digest)
	}
}

// markDigestAsCollected adds the given digest to the list of collected digests for the given repository.
// If the repository is not yet in the checkedDigest map, it will be added with an empty slice of digests.
func (o *ociCollector) markDigestAsCollected(repo string, digest string) {
	collectedDigests, ok := o.checkedDigest.Load(repo)
	if !ok {
		o.checkedDigest.Store(repo, []string{})
	}
	digests, ok := collectedDigests.([]string)
	if !ok {
		return
	}
	o.checkedDigest.Store(repo, append(digests, digest))
}

// Type is the collector type of the collector
func (o *ociCollector) Type() string {
	return OCICollector
}

// hasNoTag determines if an OCI string passed in had no tag
func hasNoTag(r ref.Ref) bool {
	// the reference parsing automatically sets the tag to latest if there is no tag
	// specified, thus we need to check the reference to see if the latest tag was actually
	// included.
	return r.Tag == "" || (r.Tag == "latest" && !strings.HasSuffix(r.Reference, ":latest"))
}

// hasNoDigest determines if an OCI string passed in had no digest
func hasNoDigest(r ref.Ref) bool {
	return r.Digest == ""
}

// hasNoIdentifier determines if an OCI string passed in had no identifier (tag
// or digest)
func hasNoIdentifier(r ref.Ref) bool {
	return hasNoTag(r) && hasNoDigest(r)
}

func getRegClientOptions() []regclient.Opt {
	rcOpts := []regclient.Opt{}
	rcOpts = append(rcOpts, regclient.WithDockerCreds())
	rcOpts = append(rcOpts, regclient.WithDockerCerts())
	rcOpts = append(rcOpts, regclient.WithUserAgent(version.UserAgent))
	return rcOpts
}
