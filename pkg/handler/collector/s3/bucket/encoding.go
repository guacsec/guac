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
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func ExtractEncoding(encoding string, filename string) processor.EncodingType {
	switch strings.ToUpper(encoding) {
	case "BZIP2":
		return processor.EncodingBzip2
	case "ZSTD":
		return processor.EncodingZstd
	default:
		return FromFile(filename)
	}
}

func FromFile(file string) processor.EncodingType {
	strs := strings.Split(file, ".")
	extension := strs[len(strs)-1]
	switch extension {
	case "bz2":
		return processor.EncodingBzip2
	case "zst":
		return processor.EncodingZstd
	default:
		return processor.EncodingUnknown
	}
}
