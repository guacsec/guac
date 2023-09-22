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

package bucket

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type BuildBucket interface {
	GetDownloader(hostname string, port string, region string) Bucket
}

type BucketBuilder struct {
}

func (bd BucketBuilder) GetBucket(hostname string, port string, region string) Bucket {
	return S3Bucket{
		hostname,
		port,
		region,
	}
}

type Bucket interface {
	DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error)
	GetEncoding(ctx context.Context, bucket string, item string) (string, error)
}

type S3Bucket struct {
	hostname string
	port     string
	region   string
}

func GetDefaultBucket(hostname string, port string, region string) Bucket {
	return S3Bucket{hostname, port, region}
}

func (d S3Bucket) DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading AWS SDK config: %v", err)
	}

	addr := fmt.Sprintf("http://%s:%s/%s/", d.hostname, d.port, bucket)
	cfg.Region = d.region

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(addr)
	})

	// Create a GetObjectInput with the bucket name and object key.
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(item),
	}

	resp, err := client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("unable to download file: %v", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	n, err := io.Copy(buf, resp.Body)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("unable to read file contents: %v", err)
	}

	return buf.Bytes(), err
}

func (d S3Bucket) GetEncoding(ctx context.Context, bucket string, item string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", fmt.Errorf("error loading AWS SDK config: %v", err)
	}

	addr := fmt.Sprintf("http://%s:%s/%s/", d.hostname, d.port, bucket)
	cfg.Region = d.region

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(addr)
	})

	headObject, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(item)})
	if err != nil {
		return "", fmt.Errorf("could not get head object: %v", err)
	}

	if headObject.ContentEncoding == nil {
		return "", nil
	}

	return *headObject.ContentEncoding, nil
}
