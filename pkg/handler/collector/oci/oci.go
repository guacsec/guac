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
// Note: OCI collector can be called upon by a upstream registry collector in the future to collect from all
// repos in a given registry. For further details see issue #298
//
// Interval should be set to about 5 mins or more for production so that it doesn't clobber registries.
func NewOCICollector(ctx context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration) *ociCollector {
	return &ociCollector{
		collectDataSource: collectDataSource,
		checkedDigest:     map[string][]string{},
		poll:              poll,
		interval:          interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	repoTags := map[string][]string{}
	logger := logging.FromContext(ctx)

	populateRepoTags := func() error {
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

			// If a image reference has no tag, then it is considered as getting all tags
			if hasNoTag(imageRef) {
				repoTags[imagePath] = []string{}
			} else {
				// if the list is equal to the empty list, it is already looking for
				// all tags
				if repoTags[imagePath] == nil || len(repoTags[imagePath]) > 0 {
					repoTags[imagePath] = append(repoTags[imagePath], imageRef.Tag)
				}

			}
		}
		return nil
	}

	if o.poll {
		for {
			err := populateRepoTags()
			if err != nil {
				return fmt.Errorf("unable to populate repotags: %w", err)
			}

			for repo, tags := range repoTags {
				// when polling if tags are specified, it will never get any new tags
				// that might be added after the fact. Defeating the point of the polling
				if len(tags) > 0 {
					return errors.New("image tag should not specified when using polling")
				}
				err = o.getTagsAndFetch(ctx, repo, tags, docChannel)
				if err != nil {
					return err
				}
			}
			time.Sleep(o.interval)
		}
	} else {
		err := populateRepoTags()
		if err != nil {
			return fmt.Errorf("unable to populate repotags: %w", err)
		}

		for repo, tags := range repoTags {
			err := o.getTagsAndFetch(ctx, repo, tags, docChannel)
			if err != nil {
				return err
			}
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
				return fmt.Errorf("reading tags for %s: %w", repo, err)
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
			return fmt.Errorf("reading tags for %s: %w", repo, err)
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
					return fmt.Errorf("reading tags for %s: %w", repo, err)
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
		return fmt.Errorf("failed to get manifest head: %w", err)
	}

	if m.IsList() {
		m, err := rc.ManifestGet(ctx, image)
		if err != nil {
			return fmt.Errorf("failed to get manifest: %w", err)
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
				return fmt.Errorf("reading tags for %s: %w", repo, err)
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
				return fmt.Errorf("failed to get layers: %w", err)
			}
			for i := len(layers) - 1; i >= 0; i-- {
				blob, err := rc.BlobGet(ctx, r, layers[i])
				if err != nil {
					return fmt.Errorf("failed pulling layer %d: %w", i, err)
				}
				btr1, err := blob.RawBody()
				if err != nil {
					return fmt.Errorf("failed reading layer %d: %w", i, err)
				}

				doc := &processor.Document{
					Blob:   btr1,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatUnknown,
					SourceInformation: processor.SourceInformation{
						Collector: string(OCICollector),
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

func contains(elems []string, v string) bool {
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
