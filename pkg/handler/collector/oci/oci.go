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
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
)

const (
	OCICollector = "OCICollector"
)

type ociCollector struct {
	collectDataSource datasource.CollectSource
	checkedDigest     map[string][]string
	poll              bool
	interval          time.Duration
}

// NewOCICollector initializes the oci collector by passing in the repo and tag being collected.
// Note: OCI collector can be called upon by an upstream registry collector in the future to collect from all
// repos in a given registry. For further details see issue #298
//
// Interval should be set to about 5 minutes or more for production so that it doesn't clobber registries.
func NewOCICollector(_ context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration) collector.Collector {
	return &ociCollector{
		collectDataSource: collectDataSource,
		checkedDigest:     map[string][]string{},
		poll:              poll,
		interval:          interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if docChannel == nil {
		return fmt.Errorf("docChannel is nil")
	}
	logger := logging.FromContext(ctx)
	// Get the data sources only once, since they do not change during the collection process
	ds, err := o.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	// Loop through each data source, get the image reference and tags, and call getTagsAndFetch
	for _, d := range ds.OciDataSources {
		imageRef, err := ref.New(d.Value)
		if err != nil {
			logger.Errorf("unable to parse OCI path: %v", d.Value)
			continue
		}
		imagePath := fmt.Sprintf("%s/%s", imageRef.Registry, imageRef.Repository)

		// If an image reference has no tag, then it is considered as getting all tags
		tags := []string{}
		if !hasNoTag(imageRef) {
			tags = []string{imageRef.Tag}
		}

		// Check for invalid input, where polling and image tag are both specified
		if o.poll && len(tags) > 0 {
			return errors.New("image tag should not be specified when using polling")
		}

		// Call getTagsAndFetch with the image path and tags, and send the resulting documents to the docChannel
		if err := o.getTagsAndFetch(ctx, imagePath, tags, docChannel); err != nil {
			return fmt.Errorf("unable to fetch OCI artifacts: %w", err)
		}
		// Sleep if in polling mode
		if o.poll {
			time.Sleep(o.interval)
		}
	}

	return nil
}

func (o *ociCollector) getTagsAndFetch(ctx context.Context, repo string, tags []string, docChannel chan<- *processor.Document) error {
	rcOpts := []regclient.Opt{}
	rcOpts = append(rcOpts, regclient.WithDockerCreds())
	rcOpts = append(rcOpts, regclient.WithDockerCerts())

	if len(tags) > 0 {
		for _, tag := range tags {
			if tag == "" {
				return errors.New("image tag not specified to fetch")
			}
			imageTag := fmt.Sprintf("%v:%v", repo, tag)
			r, err := ref.New(imageTag)
			if err != nil {
				return err
			}

			rc := regclient.New(rcOpts...)
			defer rc.Close(ctx, r)

			err = o.fetchOCIArtifacts(ctx, repo, rc, r, docChannel)
			if err != nil {
				return err
			}
		}
	} else {
		r, err := ref.New(repo)
		if err != nil {
			return err
		}

		rc := regclient.New(rcOpts...)
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
				err = o.fetchOCIArtifacts(ctx, repo, rc, r, docChannel)
				if err != nil {
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
	logger := logging.FromContext(ctx)

	// attempt to request only the headers, avoids Docker Hub rate limits
	m, err := rc.ManifestHead(ctx, image)
	if err != nil {
		return err
	}

	if m.IsList() {
		m, err := rc.ManifestGet(ctx, image)
		if err != nil {
			return err
		}
		pl, _ := manifest.GetPlatformList(m)
		for _, p := range pl {
			desc, err := manifest.GetPlatformDesc(m, p)
			if err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
			image.Digest = desc.Digest.String()
			err = o.fetchOCIArtifacts(ctx, repo, rc, image, docChannel)
			if err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
		}
	}

	digest := manifest.GetDigest(m)
	digestFormatted := fmt.Sprintf("%v-%v", digest.Algorithm(), digest.Encoded())
	suffixList := []string{"att", "sbom"}
	for _, suffix := range suffixList {
		digestTag := fmt.Sprintf("%v.%v", digestFormatted, suffix)
		// check to see if the digest + suffix has already been collected
		if !contains(o.checkedDigest[repo], digestTag) {
			imageTag := fmt.Sprintf("%v:%v", repo, digestTag)
			r, err := ref.New(imageTag)
			if err != nil {
				return err
			}

			// if `.att` or `.sbom`` do not exist for specified digest
			// log error and continue
			m, err = rc.ManifestGet(ctx, r)
			if err != nil {
				logger.Error(err)
				continue
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
				blob, err := rc.BlobGet(ctx, r, layers[i])
				if err != nil {
					return fmt.Errorf("failed pulling layer %d: %w", i, err)
				}
				btr1, err := blob.RawBody()
				if err != nil {
					return err
				}

				doc := &processor.Document{
					Blob:   btr1,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatUnknown,
					SourceInformation: processor.SourceInformation{
						Collector: OCICollector,
						Source:    imageTag,
					},
				}
				docChannel <- doc
			}
			o.checkedDigest[repo] = append(o.checkedDigest[repo], digestTag)
		}
	}

	return nil
}

func contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
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
	return r.Tag == "latest" && r.Digest == "" && !strings.HasSuffix(r.Reference, "latest")
}
