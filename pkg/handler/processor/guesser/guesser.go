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

package guesser

import (
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/sirupsen/logrus"
)

func GuessDocument(d *processor.Document) (processor.DocumentType, processor.FormatType, error) {
	format := d.Format

	if format == processor.FormatUnknown {
		for name, g := range documentFormatGuessers {
			if f := g.GuessFormat(d.Blob); f != processor.FormatUnknown {
				format = f
				logrus.Debugf("Format guesser %v guessed document format %v", name, f)
				break
			}
		}
	}

	documentType := d.Type
	if documentType == processor.DocumentUnknown {
		for name, g := range documentTypeGuessers {
			if t := g.GuessDocumentType(d.Blob, format); t != processor.DocumentUnknown {
				documentType = t
				logrus.Debugf("DocumentType guesser %v guessed document format %v", name, t)
				break
			}
		}
	}

	return documentType, format, nil
}
