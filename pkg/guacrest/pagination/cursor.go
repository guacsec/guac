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

package pagination

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

var (
	// base64 (binary to text) encoding scheme.
	//
	// Padding is not used to avoid having to url-encode the pad character.
	byteEncoding = base64.RawURLEncoding

	// integer to binary encoding scheme
	intEncoding = binary.LittleEndian
)

func indexFromCursor(cursor string) (uint64, error) {
	if len(cursor) != 11 {
		return 0, fmt.Errorf("Encoded cursor %q is not 11 bytes", cursor)
	}
	decodedBytes, err := byteEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("Cursor could not be decoded as base64: %v", err)
	}
	// decodedBytes must be at least length 8, but this is covered by the
	// string length check above
	return intEncoding.Uint64(decodedBytes), nil
}

// Produces fixed-length (11 byte) strings
func cursorFromIndex(index uint64) string {
	inputBytes := make([]byte, 8)
	intEncoding.PutUint64(inputBytes, index)
	return byteEncoding.EncodeToString(inputBytes)
}
