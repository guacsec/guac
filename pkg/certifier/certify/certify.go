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
	"errors"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	BufferChannelSize int = 1000
	maxRetries            = 10
	baseDelay             = 1 * time.Second
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
	// logger
	logger := logging.FromContext(ctx)

	runCertifier := func() error {
		// compChan to collect query components
		compChan := make(chan interface{}, BufferChannelSize)
		// errChan to receive error from collectors
		errChan := make(chan error, 1)

		// define the GetComponents operation to be retried on failure (if gql server is not up)
		backoffOperation := func() error {
			err := query.GetComponents(ctx, compChan)
			if err != nil {
				logger.Errorf("GetComponents failed with error: %v", err)
				return fmt.Errorf("GetComponents failed with error: %w", err)
			}
			return nil
		}

		go func() {
			wrappedOperation := retryWithBackoff(ctx, backoffOperation)
			errChan <- wrappedOperation()
		}()

		componentsCaptured := false
		for !componentsCaptured {
			select {
			case d := <-compChan:
				if err := generateDocuments(ctx, d, emitter, handleErr); err != nil {
					return fmt.Errorf("generate certifier documents error: %w", err)
				}
			case err := <-errChan:
				if err != nil {
					// drain channel before exiting
					drainComponentChannel(compChan, ctx, emitter, handleErr)
					return err
				}
				componentsCaptured = true
			case <-ctx.Done():
				componentsCaptured = true
			}
		}
		// drain channel before exiting
		drainComponentChannel(compChan, ctx, emitter, handleErr)
		return nil
	}

	// initially run the certifier the first time and then tick per interval if polling
	logger.Infof("Starting certifier run: %v", time.Now().UTC())
	err := runCertifier()
	if err != nil {
		return fmt.Errorf("certifier failed with an error: %w", err)
	}
	logger.Infof("Certifier run completed: %v", time.Now().UTC())

	if poll {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ticker.C:
				// add logging to determine when the certifier run is started
				logger.Infof("Starting certifier run: %v", time.Now().UTC())
				err := runCertifier()
				if err != nil {
					return fmt.Errorf("certifier failed with an error: %w", err)
				}
				// reset the interval timer and log completion of the current certifier run
				ticker.Reset(interval)
				logger.Infof("Certifier run completed: %v", time.Now().UTC())
			// if the context has been canceled return the err.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			}
		}
	}
	return nil
}

func drainComponentChannel(compChan chan interface{}, ctx context.Context, emitter certifier.Emitter, handleErr certifier.ErrHandler) {
	logger := logging.FromContext(ctx)
	for len(compChan) > 0 {
		d := <-compChan
		if err := generateDocuments(ctx, d, emitter, handleErr); err != nil {
			logger.Errorf("generate certifier documents error: %v", err)
		}
	}
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
			collector.AddChildLogger(logger, d)
			logger.Debugf("starting up the child logger: %+v", d.SourceInformation.Source)
			if err := emitter(d); err != nil {
				d.ChildLogger.Errorf("emit error: %v", err)
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
		collector.AddChildLogger(logger, d)
		logger.Debugf("starting up the child logger: %+v", d.SourceInformation.Source)
		if err := emitter(d); err != nil {
			d.ChildLogger.Errorf("emit error: %v", err)
		}
	}
	return nil
}

// retryFunc is a function that can be retried
type retryFunc func() error

// retryWithBackoff retries the given operation with exponential backoff
func retryWithBackoff(ctx context.Context, operation retryFunc) retryFunc {
	logger := logging.FromContext(ctx)
	return func() error {
		var lastError error
		var urlErr *url.Error

		for i := 0; i < maxRetries; i++ {
			err := operation()
			if err == nil {
				return nil
			}
			if errors.As(err, &urlErr) {
				secRetry := math.Pow(2, float64(i))
				logger.Infof("Retrying operation in %f seconds\n", secRetry)
				delay := time.Duration(secRetry) * baseDelay
				time.Sleep(delay)
				lastError = err
			} else {
				return err
			}
		}
		return lastError
	}
}
