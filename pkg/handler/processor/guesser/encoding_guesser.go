//
// Copyright 2024 The GUAC Authors.
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

package guesser

import (
	"bufio"
	"bytes"
	"context"
	"net/http"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	bzipMimeType = "application/x-bzip2"
	zstdMimeType = "application/zstd"
	blankType    = ""
)

func GuessEncoding(ctx context.Context, d *processor.Document) error {
	logger := logging.FromContext(ctx)

	if d.Encoding != processor.EncodingUnknown {
		return nil
	}

	mimeType, err := detectFileEncoding(d)
	if err != nil {
		return err
	}
	switch mimeType {
	case bzipMimeType:
		d.Encoding = processor.EncodingBzip2
	case zstdMimeType:
		d.Encoding = processor.EncodingZstd
	default:
	}
	if d.Encoding != "" {
		logger.Infof("byte analysis detected encoding:  %v", d.Encoding)
	}

	return nil
}

// This method examines the first few bytes of the file to determine the
// encoding from the headers etc
//
// It detects a zstd encoding if the first 4 bytes equal 0xFD2FB528 in
// little-endian format as detailed here: https://www.ietf.org/rfc/rfc8878.txt
//
// and bzip2 encoding is identified by the initial three-octet string 0x42,
// 0x5A, 0x68.  as detailed by: https://www.ietf.org/rfc/rfc5655.txt
func detectFileEncoding(i *processor.Document) (string, error) {

	// create a bufio.Reader so we can 'peek' at the first few bytes without
	// consuming
	bReader := bytes.NewReader(i.Blob)
	reader := bufio.NewReader(bReader)

	if len(i.Blob) < 16 {
		return blankType, nil
	}

	testBytes, err := reader.Peek(16)
	if err != nil {
		return "", err
	}

	// find the content mime-type from the first few bytes
	contentType := http.DetectContentType(i.Blob)
	// octet-stream is the default meaning that no encoding has been found
	if contentType == "application/octet-stream" {
		if testBytes[0] == 0x42 && testBytes[1] == 0x5A && testBytes[2] == 0x68 {
			return "application/x-bzip2", nil
		}
		if testBytes[3] == 0xFD && testBytes[2] == 0x2F && testBytes[1] == 0xB5 &&
			testBytes[0] == 0x28 {
			return "application/zstd", nil
		}
	}
	return contentType, nil
}
