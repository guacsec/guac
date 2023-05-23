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
	"time"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	BufferChannelSize int = 1000
)

var (
	documentCertifier     = map[certifier.CertifierType]func() certifier.Certifier{}
	errCertifierOverwrite = fmt.Errorf("the certifier is being overwritten")
)

func certifierTypeOverwriteError(certifierType certifier.CertifierType) error {
	return fmt.Errorf("%w: %s", errCertifierOverwrite, certifierType)
}

// RegisterCertifier registers the active certifier for to generate attestations
func RegisterCertifier(c func() certifier.Certifier, certifierType certifier.CertifierType) error {
	if _, ok := documentCertifier[certifierType]; ok {
		documentCertifier[certifierType] = c
		return certifierTypeOverwriteError(certifierType)
	}
	documentCertifier[certifierType] = c

	return nil
}

// Certify queries the graph DB to get the components to scan. Utilizing the registered certifiers,
// it generates new nodes and attestations.
func Certify(ctx context.Context, query certifier.QueryComponents, emitter certifier.Emitter, handleErr certifier.ErrHandler, poll bool, interval time.Duration) error {

	runCertifier := func() error {
		// compChan to collect query components
		compChan := make(chan interface{}, BufferChannelSize)
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
					return fmt.Errorf("generate certifier documents error: %w", err)
				}
			case err := <-errChan:
				if !handleErr(err) {
					return err
				}
				componentsCaptured = true
			case <-ctx.Done():
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

	// initially run the certifier the first time and then tick per interval if polling
	err := runCertifier()
	if err != nil {
		return fmt.Errorf("certifier failed with an error: %w", err)
	}

	if poll {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ticker.C:
				err := runCertifier()
				if err != nil {
					return fmt.Errorf("certifier failed with an error: %w", err)
				}
				ticker.Reset(interval)
			// if the context has been canceled return the err.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			}
		}
	}
	return nil
}

// generateDocuments runs CertifyVulns as a goroutine to scan and generates attestations that
// are emitted as processor documents to be ingested
func generateDocuments(ctx context.Context, collectedComponent interface{}, emitter certifier.Emitter, handleErr certifier.ErrHandler) error {
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
		case <-ctx.Done():
			certifiersDone = numCertifiers
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
