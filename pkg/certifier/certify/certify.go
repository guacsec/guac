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

package certify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	BufferChannelSize int = 1000
)

func init() {
	_ = RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV)
}

var (
	documentCertifier = map[certifier.CertifierType]func() certifier.Certifier{}
)

// RegisterCertifier registers the active certifier for to generate attestations
func RegisterCertifier(c func() certifier.Certifier, certifierType certifier.CertifierType) error {
	if _, ok := documentCertifier[certifierType]; ok {
		return fmt.Errorf("the certifier is being overwritten: %s", certifierType)
	}
	documentCertifier[certifierType] = c

	return nil
}

// Certify queries the graph DB to get the packages to scan. Utilizing the registered certifiers,
// it scans and generate vulnerability attestation for each package. Aggregating the results to the
// top/root level package
func Certify(ctx context.Context, query certifier.QueryComponents, emitter certifier.Emitter, handleErr certifier.ErrHandler) error {

	// docChan to collect artifacts
	compChan := make(chan *certifier.Component, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)
	// logger
	logger := logging.FromContext(ctx)

	go func() {
		errChan <- query.GetComponents(ctx, compChan)
	}()

	componentsCaptured := false
	for !componentsCaptured {
		select {
		case d := <-compChan:
			if err := generateDocuments(ctx, d, emitter, handleErr); err != nil {
				logger.Errorf("generate certifier documents error: %v", err)
			}
		case err := <-errChan:
			if !handleErr(err) {
				return err
			}
			componentsCaptured = true
		}
	}
	for len(compChan) > 0 {
		d := <-compChan
		if err := generateDocuments(ctx, d, emitter, handleErr); err != nil {
			logger.Errorf("generate certifier documents error: %v", err)
		}
	}

	return nil
}

// generateDocuments runs CertifyVulns as a goroutine to scan and generate a vulnerability certification that
// are emitted as processor documents to be ingested
func generateDocuments(ctx context.Context, collectedComponent *certifier.Component, emitter certifier.Emitter, handleErr certifier.ErrHandler) error {

	// docChan to collect artifacts
	docChan := make(chan *processor.Document, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, len(documentCertifier))
	// logger
	logger := logging.FromContext(ctx)

	for _, certifier := range documentCertifier {
		c := certifier()
		go func() {
			errChan <- c.CertifyComponent(ctx, collectedComponent, docChan)
		}()
	}

	numCertifiers := len(documentCertifier)
	certifiersDone := 0
	for certifiersDone < numCertifiers {
		select {
		case d := <-docChan:
			if err := emitter(d); err != nil {
				logger.Errorf("emit error: %v", err)
			}
		case err := <-errChan:
			if !handleErr(err) {
				return err
			}
			certifiersDone += 1
		}
	}
	for len(docChan) > 0 {
		d := <-docChan
		if err := emitter(d); err != nil {
			logger.Errorf("emit error: %v", err)
		}
	}
	return nil
}

// Publish is used by NATS JetStream to stream the documents and send them to the processor
func Publish(ctx context.Context, d *processor.Document) error {
	logger := logging.FromContext(ctx)
	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	err = emitter.Publish(ctx, emitter.SubjectNameDocCollected, docByte)
	if err != nil {
		return err
	}
	logger.Debugf("doc published: %+v", d.SourceInformation.Source)
	return nil
}
