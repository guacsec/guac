//
// Copyright 2023 The GUAC Authors.
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

package s3

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/guacsec/guac/pkg/handler/collector/s3/bucket"
	"github.com/guacsec/guac/pkg/handler/collector/s3/messaging"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	S3CollectorType = "S3CollectorType"
)

type S3Collector struct {
	config S3CollectorConfig
}

type S3CollectorConfig struct {
	MessageProvider         string
	MessageProviderEndpoint string                           // optional if using the sqs message provider
	S3Url                   string                           // optional (uses aws sdk defaults)
	S3Bucket                string                           // bucket name to collect from
	S3Item                  string                           // optional (only for non-polling behaviour)
	S3Region                string                           // optional (defaults to us-east-1, assumes same region for s3 and sqs)
	Queues                  string                           // optional (comma-separated list of queues/topics)
	MpBuilder               messaging.MessageProviderBuilder // optional
	BucketBuilder           bucket.BuildBucket               // optional
	Poll                    bool
}

func NewS3Collector(cfg S3CollectorConfig) *S3Collector {
	s3collector := &S3Collector{
		config: cfg,
	}
	return s3collector
}

func (s *S3Collector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {

	if s.config.Poll {
		retrieveWithPoll(*s, ctx, docChannel)
	} else {
		return retrieve(*s, ctx, docChannel)
	}

	return nil
}

func retrieve(s S3Collector, ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	downloader := getDownloader(s)

	item := s.config.S3Item
	if len(item) > 0 {
		blob, err := downloader.DownloadFile(ctx, s.config.S3Bucket, item)
		if err != nil {
			logger.Errorf("could not download item %v: %v", item, err)
			return err
		}

		enc, err := downloader.GetEncoding(ctx, s.config.S3Bucket, item)
		if err != nil {
			logger.Errorf("could not get encoding for item %v: %v", item, err)
			return err
		}

		doc := &processor.Document{
			Blob:     blob,
			Type:     processor.DocumentUnknown,
			Format:   processor.FormatUnknown,
			Encoding: bucket.ExtractEncoding(enc, item),
			SourceInformation: processor.SourceInformation{
				Collector: S3CollectorType,
				Source:    "S3",
			},
		}
		docChannel <- doc
	} else {
		var token *string
		const MaxKeys = 100
		for {
			files, t, err := downloader.ListFiles(ctx, s.config.S3Bucket, token, MaxKeys)
			if err != nil {
				logger.Errorf("could not list files %v: %v", item, err)
				return err
			}
			token = t

			for _, item := range files {
				blob, err := downloader.DownloadFile(ctx, s.config.S3Bucket, item)
				if err != nil {
					logger.Errorf("could not download item %v, skipping: %v", item, err)
					continue
				}

				enc, err := downloader.GetEncoding(ctx, s.config.S3Bucket, item)
				if err != nil {
					logger.Errorf("could not get encoding for item %v, skipping: %v", item, err)
					continue
				}

				doc := &processor.Document{
					Blob:     blob,
					Type:     processor.DocumentUnknown,
					Format:   processor.FormatUnknown,
					Encoding: bucket.ExtractEncoding(enc, item),
					SourceInformation: processor.SourceInformation{
						Collector: S3CollectorType,
						Source:    "S3",
					},
				}
				docChannel <- doc
			}

			if len(files) < MaxKeys {
				break
			}

		}

	}

	return nil
}

func retrieveWithPoll(s S3Collector, ctx context.Context, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)
	downloader := getDownloader(s)
	queues := strings.Split(s.config.Queues, ",")

	var wg sync.WaitGroup
	for _, queue := range queues {
		wg.Add(1)

		go func(wg *sync.WaitGroup, cncCtx context.Context, queue string) {
			defer wg.Done()

			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("recovered from panic: %v", r)
				}
			}()

			mp, err := getMessageProvider(s, queue)
			if err != nil {
				logger.Errorf("error getting message provider for queue %v: %v", queue, err)
				return
			}
			defer mp.Close(cncCtx)

			for {
				select {
				case <-cncCtx.Done():
					logger.Infof("Shutting down collector for queue %s...\n", queue)
					return
				default:
					m, err := mp.ReceiveMessage(cncCtx)
					if err != nil {
						logger.Infof("error while receiving message, skipping: %v\n", err)
						continue
					}

					if e, er := m.GetEvent(); e != messaging.PUT {
						if er != nil {
							logger.Debugf("skipping message: %v\n", er)
						}
						continue
					}
					bucketName, err := m.GetBucket()
					if err != nil {
						logger.Errorf("skipping message: %v\n", err)
						continue
					}
					item, err := m.GetItem()
					if err != nil {
						logger.Errorf("skipping message: %v\n", err)
						continue
					}

					blob, err := downloader.DownloadFile(cncCtx, bucketName, item)
					if err != nil {
						logger.Errorf("could not download item %v, skipping: %v", item, err)
						continue
					}

					enc, err := downloader.GetEncoding(cncCtx, bucketName, item)
					if err != nil {
						logger.Errorf("could not get encoding for item %v, skipping: %v", item, err)
						continue
					}

					doc := &processor.Document{
						Blob:     blob,
						Type:     processor.DocumentUnknown,
						Format:   processor.FormatUnknown,
						Encoding: bucket.ExtractEncoding(enc, item),
						SourceInformation: processor.SourceInformation{
							Collector: S3CollectorType,
							Source:    "S3",
						},
					}
					select {
					case docChannel <- doc:
					case <-cncCtx.Done():
						logger.Infof("Shutting down collector for queue %s...\n", queue)
						return
					}
				}
			}

		}(&wg, ctx, queue)
	}

	wg.Wait()
}

func getMessageProvider(s S3Collector, queue string) (messaging.MessageProvider, error) {
	var err error
	var mpBuilder messaging.MessageProviderBuilder
	if s.config.MpBuilder != nil {
		mpBuilder = s.config.MpBuilder
	} else {
		mpBuilder = messaging.GetDefaultMessageProviderBuilder()
		if err != nil {
			return nil, fmt.Errorf("error getting message provider: %w", err)
		}
	}

	mp, err := mpBuilder.GetMessageProvider(messaging.MessageProviderConfig{
		Queue:    queue,
		Endpoint: s.config.MessageProviderEndpoint,
		Provider: s.config.MessageProvider,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating message provider: %s", err)
	}

	return mp, nil
}

func getDownloader(s S3Collector) bucket.Bucket {
	var downloader bucket.Bucket
	if s.config.BucketBuilder != nil {
		downloader = s.config.BucketBuilder.GetDownloader(s.config.S3Url, s.config.S3Region)
	} else {
		downloader = bucket.GetDefaultBucket(s.config.S3Url, s.config.S3Region)
	}
	return downloader
}

func (s *S3Collector) Type() string {
	return S3CollectorType
}
