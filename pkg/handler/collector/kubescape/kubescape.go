//
// Copyright 2025 The GUAC Authors.
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

// package kubescape implements the Kubescape collector that gets sbom obejects
// from the Kubernetes apiserver and passes them to the ingestor.
package kubescape

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/sbom"
	scv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	Type = "KubescapeCollectorType"
)

type collector struct {
	config Config
}

// Config is passed to New() to create a collector object
type Config struct {
	Watch     bool   // True will watch for sbom objects, false will just list once and return
	Namespace string // NS to search in, Should be "kubescape"
	Filtered  bool   // True to search for SBOMSyftFiltereds, otherwise SBOMSyfts
}

var list func(ctx context.Context, sc *kssc.Clientset, ns string) (*scv1beta1.SBOMSyftList, error)
var listFiltered func(ctx context.Context, sc *kssc.Clientset, ns string) (*scv1beta1.SBOMSyftFilteredList, error)
var get func(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSyft, error)
var getFiltered func(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSyftFiltered, error)
var ksscNewForConfig func(c *rest.Config) (*kssc.Clientset, error)
var restInClusterConfig func() (*rest.Config, error)
var formatDecode func(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error)
var formatEncode func(s sbom.SBOM, f sbom.FormatEncoder) ([]byte, error)

func init() {
	list = listReal
	listFiltered = listFilteredReal
	get = getReal
	getFiltered = getFilteredReal
	ksscNewForConfig = kssc.NewForConfig
	restInClusterConfig = rest.InClusterConfig
	formatDecode = format.Decode
	formatEncode = format.Encode
}

// New returns a new collector with saved config conforming to
// guac/pkg/handler/collector.Collector interface.
func New(cfg Config) *collector {
	return &collector{
		config: cfg,
	}
}

// Conforming to guac/pkg/handler/collector.Collector interface, retrieve sboms
// on dc channel.
func (coll *collector) RetrieveArtifacts(ctx context.Context, dc chan<- *processor.Document) error {
	// Setup client
	c, err := restInClusterConfig()
	if err != nil {
		return fmt.Errorf("error getting in cluster config: %w", err)
	}
	sc, err := ksscNewForConfig(c)
	if err != nil {
		return fmt.Errorf("error creating kubescape storage client: %w", err)
	}

	// Either watch or list
	if coll.config.Watch {
		return coll.watch(ctx, dc, sc)
	}
	return coll.list(ctx, dc, sc)
}

func (coll *collector) list(ctx context.Context, dc chan<- *processor.Document, sc *kssc.Clientset) error {
	// List sboms and call get() on each one
	if coll.config.Filtered {
		sboms, err := listFiltered(ctx, sc, coll.config.Namespace)
		if err != nil {
			return fmt.Errorf("error listing sboms in cluster: %w", err)
		}
		for _, s := range sboms.Items {
			err := coll.get(ctx, dc, sc, s.Name)
			if err != nil {
				return fmt.Errorf("error processing sbom %q: %w", s.Name, err)
			}
		}
	} else {
		sboms, err := list(ctx, sc, coll.config.Namespace)
		if err != nil {
			return fmt.Errorf("error listing sboms in cluster: %w", err)
		}
		for _, s := range sboms.Items {
			err := coll.get(ctx, dc, sc, s.Name)
			if err != nil {
				return fmt.Errorf("error processing sbom %q: %w", s.Name, err)
			}
		}
	}
	close(dc)
	return nil
}

func (coll *collector) watch(ctx context.Context, dc chan<- *processor.Document, sc *kssc.Clientset) error {
	logger := logging.FromContext(ctx)

	for ctx.Err() == nil {
		var w watch.Interface
		if coll.config.Filtered {
			watch, err := sc.SpdxV1beta1().SBOMSyftFiltereds(coll.config.Namespace).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("error watching sboms: %w", err)
			}
			w = watch
		} else {
			watch, err := sc.SpdxV1beta1().SBOMSyfts(coll.config.Namespace).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("error watching sboms: %w", err)
			}
			w = watch
		}
		ch := w.ResultChan()

		var done bool
		for !done {
			select {
			case e, open := <-ch:
				if e.Type == watch.Added || e.Type == watch.Modified {
					var name string
					obj, ok := e.Object.(*scv1beta1.SBOMSyft)
					if ok {
						name = obj.Name
					} else {
						obj, ok := e.Object.(*scv1beta1.SBOMSyft)
						if ok {
							name = obj.Name
						} else {
							break
						}
					}
					err := coll.get(ctx, dc, sc, name)
					if err != nil {
						logger.Errorf("error processing sbom %q, continuing watch: %s", name, err)
					}
				}
				if e.Type == watch.Error {
					logger.Warn("Watch error, restarting watch.")
					done = true
				}
				if !open {
					logger.Warn("Watch closed, restarting watch.")
					done = true
				}
			case <-ctx.Done():
				logger.Warn("Context cancelled, exiting Kubescape collector")
				done = true
			}
		}
		w.Stop()
	}
	close(dc)

	return nil
}

func (coll *collector) get(ctx context.Context, dc chan<- *processor.Document, sc *kssc.Clientset, name string) error {
	logger := logging.FromContext(ctx)

	// Get SBOM
	var sft *scv1beta1.SyftDocument
	if coll.config.Filtered {
		s, err := getFiltered(ctx, sc, coll.config.Namespace, name)
		if err != nil {
			return fmt.Errorf("error getting sbom %q: %w", name, err)
		}
		if s.Annotations["kubescape.io/status"] == "too-large" {
			logger.Warnf("Found sbom object but was too large for api server %q", name)
			return nil
		}
		sft = &s.Spec.Syft
	} else {
		s, err := get(ctx, sc, coll.config.Namespace, name)
		if err != nil {
			return fmt.Errorf("error getting sbom %q: %w", name, err)
		}
		if s.Annotations["kubescape.io/status"] == "too-large" {
			logger.Warnf("Found sbom object but was too large for api server %q", name)
			return nil
		}
		sft = &s.Spec.Syft
	}

	// Convert from Syft to CDX
	bts, err := json.Marshal(sft)
	if err != nil {
		return fmt.Errorf("error unmarshaling sbom: %w", err)
	}
	reader := bytes.NewReader(bts)
	syft, _, _, err := formatDecode(reader)
	if err != nil {
		return fmt.Errorf("could not decode sbom as syft format: %w", err)
	}
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return fmt.Errorf("could not create cyclonedx encoder: %w", err)
	}
	cdxBts, err := formatEncode(*syft, enc)
	if err != nil {
		return fmt.Errorf("could not encode syft sbom as cyclonedx: %w", err)
	}

	// Send to GUAC
	doc := &processor.Document{
		Blob:     cdxBts,
		Type:     processor.DocumentCycloneDX,
		Format:   processor.FormatJSON,
		Encoding: processor.EncodingUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   Type,
			Source:      name,
			DocumentRef: events.GetDocRef(cdxBts),
		},
	}
	dc <- doc
	return nil
}

// Type returns type string
func (s *collector) Type() string {
	return Type
}

func listReal(ctx context.Context, sc *kssc.Clientset, ns string) (*scv1beta1.SBOMSyftList, error) {
	return sc.SpdxV1beta1().SBOMSyfts(ns).List(ctx, metav1.ListOptions{})
}

func listFilteredReal(ctx context.Context, sc *kssc.Clientset, ns string) (*scv1beta1.SBOMSyftFilteredList, error) {
	return sc.SpdxV1beta1().SBOMSyftFiltereds(ns).List(ctx, metav1.ListOptions{})
}

func getReal(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSyft, error) {
	return sc.SpdxV1beta1().SBOMSyfts(ns).Get(ctx, name, metav1.GetOptions{})
}

func getFilteredReal(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSyftFiltered, error) {
	return sc.SpdxV1beta1().SBOMSyftFiltereds(ns).Get(ctx, name, metav1.GetOptions{})
}
