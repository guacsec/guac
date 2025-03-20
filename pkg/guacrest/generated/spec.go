// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
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

	"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",
	"//++9T+Gqx0AAA==",
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
