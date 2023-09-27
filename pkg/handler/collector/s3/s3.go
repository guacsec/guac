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
	"os"
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
	MessageProvider     string
	MessageProviderHost string
	MessageProviderPort string
	S3Host              string
	S3Port              string
	S3Bucket            string
	S3Item              string
	Region              string // optional (defaults to us-east-1, assumes same region for s3 and sqs)
	Queues              string
	MpBuilder           messaging.MessageProviderBuilder // optional
	BucketBuilder       bucket.BuildBucket               // optional
	SigChan             chan os.Signal                   // optional
	Poll                bool
}

func NewS3Collector(cfg S3CollectorConfig) *S3Collector {
	s3collector := &S3Collector{
		config: cfg,
	}
	return s3collector
}

func (s S3Collector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {

	if s.config.Poll {
		retrieveWithPoll(s, ctx, docChannel)
	} else {
		retrieve(s, ctx, docChannel)
	}

	return nil
}

func retrieve(s S3Collector, ctx context.Context, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)
	downloader := getDownloader(s)

	bckt := s.config.S3Bucket
	item := s.config.S3Item

	blob, err := downloader.DownloadFile(ctx, bckt, item)
	if err != nil {
		logger.Errorf("could not download item %v: %v", item, err)
		return
	}

	enc, err := downloader.GetEncoding(ctx, bckt, item)
	if err != nil {
		logger.Errorf("could not get encoding for item %v: %v", item, err)
		return
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

func retrieveWithPoll(s S3Collector, ctx context.Context, docChannel chan<- *processor.Document) {
	logger := logging.FromContext(ctx)
	downloader := getDownloader(s)
	queues := strings.Split(s.config.Queues, ",")
	sigChan := s.config.SigChan

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Send cancellation in case of receiving SIGINT
	go func(cancel context.CancelFunc) {
		<-sigChan
		cancel()
	}(cancel)

	var wg sync.WaitGroup
	for _, queue := range queues {
		wg.Add(1)

		go func(wg *sync.WaitGroup, cncCtx context.Context, queue string) {
			defer wg.Done()

			defer func() {
				if r := recover(); r != nil {
					fmt.Println("recovered from panic:", r)
				}
			}()

			mp, err := getMessageProvider(s, queue)
			if err != nil {
				logger.Errorf("error getting message provider for queue %v: %v", queue, err)
				return
			}

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
					docChannel <- doc
				}
			}

		}(&wg, cancelCtx, queue)
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
		Host:     s.config.MessageProviderHost,
		Port:     s.config.MessageProviderPort,
		Provider: s.config.MessageProvider,
		Region:   s.config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating message provider: %s", err)
	}

	return mp, nil
}

func getDownloader(s S3Collector) bucket.Bucket {
	var downloader bucket.Bucket
	if s.config.BucketBuilder != nil {
		downloader = s.config.BucketBuilder.GetDownloader(s.config.S3Host, s.config.S3Port, s.config.Region)
	} else {
		downloader = bucket.GetDefaultBucket(s.config.S3Host, s.config.S3Port, s.config.Region)
	}
	return downloader
}

func (s S3Collector) Type() string {
	return S3CollectorType
}
