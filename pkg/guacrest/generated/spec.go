// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.1.0 DO NOT EDIT.
package generated

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+RUT0/8Rgz9KpZb6SdVKVnR9pJb6V+kSq2AG3AYJt7NQOIZPBNQQPnulSebdEG77XLg",
	"1NskM7afn9/zK1rfBc/EKWL1ikIxeI6UP85M/ZtJ9GwG/bKeE3HSowmhddYk57m8j571X7QNdUZPXwut",
	"scKvyn9Sl9NtLH8R8YLjOBZYU7TigibBCq8agkjyRALE1vecSKgGw0AaAtYzk02ON5A8pIagNsnAnbEP",
	"xDWOhaK9oMeeYvp8tGemBpmKFRB724CJsBbfgeMn07oavEDnYlS8wYjpKJFEhXmunbFpL3OzU4VPxzsX",
	"hakqbB8W+Fcv7R/ug5S5RF38LyyaWSukIRBWaETMsA/aj9C6mMCvIfTSRtQX2xxaYiEoiA8kyU3S7ChG",
	"syE9bgvEJI43OVwn44RqrK6Xh7cLEn93TzbNze/LMBboeO2x4r5tC/SB2ASHFX53sjpZYYHBpCbDKA2b",
	"doguljUF4prYbgFuKBOpmDON57X2qq9f6Ofdt5pt0Ud1/brPF14SeKlJlCbVfjD2wWwo3jDAN/BlnbXI",
	"dvgC38LVzj08u9TkiMZtGooJuO/upjwz4jRnidYLWSP14Sytf9Ykfwbiy8tfYYmYTjeMyhxW+NiTDFgg",
	"my4z6yXh7lyS9FTsKIq473RaSyOot9vkO7NbRnRbvF1Vp6vVIUEu78pF7GOB3x8TsLNSxgJ/OCZkn71z",
	"7OlR5eZ9m13Qd52RQe2rY3LrIc+g8zGB64KXZDjBG+FpWNmQaVPzclCFv+f7nxqyD7ifxqM3wR7nvF88",
	"tUZTzNC3C95FmDC+73NCBlah7QRMbWVNHeezC0ri6OlDRsu26qWdLbbYY7bBAW1rzL9q+/8t3XkUbzjV",
	"eSjPZuF2HMfx7wAAAP//2OEUMowIAAA=",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
