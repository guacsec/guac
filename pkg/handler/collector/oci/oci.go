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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

const (
	OCICollector     = "OCICollector"
	DockerAPIVersion = "1.38"
)

type ociCollector struct {
	repoRef     string
	lastChecked time.Time
	poll        bool
	interval    time.Duration
}

func NewOCICollector(ctx context.Context, repoRef string, poll bool, interval time.Duration) *ociCollector {
	return &ociCollector{
		repoRef:  repoRef,
		poll:     poll,
		interval: interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time

// need to figure out the polling piece. How to when know when to pull again
// Based on the image find all its tags and keep track of the tags we have
// already looked at? Most likely will have to do it based on the timestamp
// grab the newest tags and pull down the attestation, sbom and signature.
// for all configured images in the specified registry

// need to ask BMITCH or someone to know when to pull again...

// v1.Image does contain a configuration file that contains the created at...
// list all the tags and check the time stamp on them all to which one are the
// new ones that have not been ingested via the v1.image config file/

func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	opts := crane.GetOptions()
	if o.poll {
		for {
			err := o.getTagsAndFetch(ctx, opts, docChannel)
			if err != nil {
				return err
			}
			o.lastChecked = time.Now()
			time.Sleep(o.interval)
		}
	} else {
		err := o.getTagsAndFetch(ctx, opts, docChannel)
		if err != nil {
			return err
		}
		o.lastChecked = time.Now()
	}

	return nil
}

func (o *ociCollector) getTagsAndFetch(ctx context.Context, opts crane.Options, docChannel chan<- *processor.Document) error {
	tags, err := crane.ListTags(o.repoRef)
	if err != nil {
		return fmt.Errorf("reading tags for %s: %w", o.repoRef, err)
	}

	for _, tag := range tags {
		fmt.Println(tag)
		if !strings.HasSuffix(tag, "sbom") && !strings.HasSuffix(tag, "att") && !strings.HasSuffix(tag, "sig") {
			imageTag := fmt.Sprintf("%v:%v", o.repoRef, tag)
			ref, err := name.ParseReference(imageTag, opts.Name...)
			if err != nil {
				return fmt.Errorf("parsing reference %q: %w", imageTag, err)
			}
			img, err := remote.Image(ref, opts.Remote...)
			if err != nil {
				return fmt.Errorf("reading image %q: %w", ref, err)
			}
			imgConfig, err := img.ConfigFile()
			if err != nil {
				return err
			}
			if o.poll {
				fmt.Println(imgConfig.Created.String())
				if imgConfig.Created.After(o.lastChecked) {
					err := fetchOCIArtifacts(ctx, imageTag, docChannel)
					if err != nil {
						return err
					}
				}
			} else {
				err := fetchOCIArtifacts(ctx, imageTag, docChannel)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func fetchOCIArtifacts(ctx context.Context, image string, docChannel chan<- *processor.Document) error {
	regOpts := &options.RegistryOptions{}

	ref, err := name.ParseReference(image)
	if err != nil {
		return err
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	for _, att := range attestations {
		blob, err := json.Marshal(att)
		if err != nil {
			return err
		}

		doc := &processor.Document{
			Blob:   blob,
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(OCICollector),
				Source:    fmt.Sprintf("oci:///%s", image),
			},
		}
		docChannel <- doc
	}

	sbomBlob, err := fetchSBOM(ctx, ociremoteOpts, ref)
	if err != nil && errors.Is(err, errors.New("no sbom attached to reference")) {
		return err
	}
	if len(sbomBlob) > 0 {
		doc := &processor.Document{
			Blob:   sbomBlob,
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(OCICollector),
				Source:    fmt.Sprintf("oci:///%s", image),
			},
		}
		docChannel <- doc
	}
	return nil
}

// Type returns the collector type
func (o *ociCollector) Type() string {
	return OCICollector
}

type platformList []struct {
	hash     v1.Hash
	platform *v1.Platform
}

func (pl *platformList) String() string {
	r := []string{}
	for _, p := range *pl {
		r = append(r, p.platform.String())
	}
	return strings.Join(r, ", ")
}

func fetchSBOM(ctx context.Context, ociremoteOpts []ociremote.Option, ref name.Reference) ([]byte, error) {
	dnOpts := &options.SBOMDownloadOptions{}
	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	if err != nil {
		return nil, err
	}

	idx, isIndex := se.(oci.SignedImageIndex)

	// We only allow --platform on multiarch indexes
	if dnOpts.Platform != "" && !isIndex {
		return nil, fmt.Errorf("specified reference is not a multiarch image")
	}

	if dnOpts.Platform != "" && isIndex {
		targetPlatform, err := v1.ParsePlatform(dnOpts.Platform)
		if err != nil {
			return nil, fmt.Errorf("parsing platform: %w", err)
		}
		platforms, err := getIndexPlatforms(idx)
		if err != nil {
			return nil, fmt.Errorf("getting available platforms: %w", err)
		}

		platforms = matchPlatform(targetPlatform, platforms)
		if len(platforms) == 0 {
			return nil, fmt.Errorf("unable to find an SBOM for %s", targetPlatform.String())
		}
		if len(platforms) > 1 {
			return nil, fmt.Errorf(
				"platform spec matches more than one image architecture: %s",
				platforms.String(),
			)
		}

		nse, err := idx.SignedImage(platforms[0].hash)
		if err != nil {
			return nil, fmt.Errorf("searching for %s image: %w", platforms[0].hash.String(), err)
		}
		if nse == nil {
			return nil, fmt.Errorf("unable to find image %s", platforms[0].hash.String())
		}
		se = nse
	}

	file, err := se.Attachment("sbom")
	if errors.Is(err, ociremote.ErrImageNotFound) {
		if !isIndex {
			return nil, errors.New("no sbom attached to reference")
		}
		// Help the user with the available architectures
		pl, err := getIndexPlatforms(idx)
		if len(pl) > 0 && err == nil {
			fmt.Fprintf(
				os.Stderr,
				"\nThis multiarch image does not have an SBOM attached at the index level.\n"+
					"Try using --platform with one of the following architectures:\n%s\n\n",
				pl.String(),
			)
		}
		return nil, fmt.Errorf("no SBOM found attached to image index")
	} else if err != nil {
		return nil, fmt.Errorf("getting sbom attachment: %w", err)
	}

	sbom, err := file.Payload()
	if err != nil {
		return nil, err
	}
	return sbom, nil
}

func getIndexPlatforms(idx oci.SignedImageIndex) (platformList, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("fetching index manifest: %w", err)
	}

	platforms := platformList{}
	for _, m := range im.Manifests {
		if m.Platform == nil {
			continue
		}
		platforms = append(platforms, struct {
			hash     v1.Hash
			platform *v1.Platform
		}{m.Digest, m.Platform})
	}
	return platforms, nil
}

// matchPlatform filters a list of platforms returning only those matching
// a base. "Based" on ko's internal equivalent while it moves to GGCR.
// https://github.com/google/ko/blob/e6a7a37e26d82a8b2bb6df991c5a6cf6b2728794/pkg/build/gobuild.go#L1020
func matchPlatform(base *v1.Platform, list platformList) platformList {
	ret := platformList{}
	for _, p := range list {
		if base.OS != "" && base.OS != p.platform.OS {
			continue
		}
		if base.Architecture != "" && base.Architecture != p.platform.Architecture {
			continue
		}
		if base.Variant != "" && base.Variant != p.platform.Variant {
			continue
		}

		if base.OSVersion != "" && p.platform.OSVersion != base.OSVersion {
			if base.OS != "windows" {
				continue
			} else {
				if pcount, bcount := strings.Count(base.OSVersion, "."), strings.Count(p.platform.OSVersion, "."); pcount == 2 && bcount == 3 {
					if base.OSVersion != p.platform.OSVersion[:strings.LastIndex(p.platform.OSVersion, ".")] {
						continue
					}
				} else {
					continue
				}
			}
		}
		ret = append(ret, p)
	}

	return ret
}
