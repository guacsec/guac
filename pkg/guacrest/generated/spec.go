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

	"H4sIAAAAAAAC/9RX32/bNhD+Vw7cAG+DZgfd9pK3Jm3XAP0R1AH20PaBIc8WG4pUjqQ9tfD/Phwl2ZIr",
	"r+mAPOxNEnm87767+476IpSvau/QxSDOv4hakqwwIuW3a7k2Tkbj3bJGxV80BkWm5k/iXNyUCPV+Dyjv",
	"VmadqH1beYJYItwnpGb+wQH8ArNrucal+YwzCDUqszIY8iaXqlsk8CsgDMnGAIQxkUPdGV4mCp5mYA4r",
	"cNtATbgxPgVQ0toA0unBwdtSRsaHEH1n9cGJQhjGnmGJQjhZoTgX9TjUQgRVYiUzJ+RrpGgwc9IC4afY",
	"1GwZIhm3FrtC9MENFo2LuEYSu13Rf/K3n1BFseNPhKH2LrQnX0j9p4y4lQ2/Ke8iusiPsq6tURnc4lNg",
	"5r8M4P1IuBLn4ofFIZOLdjUsnhN5al19nbmAtEECdMonF5FQg3SAbMKpdKiicWvmjjOkZZRwK9UdOs3B",
	"Xkj9Du8Thvj4aC+kBmqdFRCSKkEGWJGvwLiNtEaDJ6hMCIx3UMK7QlxxZE7aZQ629fDoeHun0HqFbiNX",
	"iLqTa3wjK3xlvpM5E7EK34I0cCAOJSeJZDMF9ClYEyK3Xd0aArdDgK2JJWfdEGis0Wl0EXKZZFKvE9nv",
	"xj9uo4O0XLmV/3ZYo91HEB7GTCI7QQn34H0yhFqcvz9GNXDzcbJ/T7KZyIZ8euee0e2Lb8zEawxBrnFC",
	"UY7A9Ru/hjIqrK89POtTeMkZnFKnQvSW36bwCFU2LI59TGM8TvmYvkvvojSuHQgqy2wn3GRwg1B5yuMG",
	"wxyuVryLECQhOJ/XCoA3+HdsBRq2xlq4RXDGzrPqjzk57JyU8hsfpT1J124qOiZnIoc7njccrkvWFsLX",
	"6GRtxLn4bX42P2NcMpYZ0kI6aZtgwqLvOdWBXWOGwfhb/jRXG+/+jM+Ge4vRAH8/nc7DlsXRgN8VUxM+",
	"eIrgSbfzOeaZn6stdLN5lbXZqWYGv8LNYH2vI1CadYkhDub8Xlf6U4LyhEqSPn2K9Vs+5G2Nbrl8AXuL",
	"9unkbOcAxLBqIyUcTnh0qeJa3geS5393+KCW90n9eDS6n5ydnWqe/b7FsfjvCvH7Q+wGk3ZXiD8eYjI1",
	"9bLtkwe5668hWcBSVUlqeKpxtsyqyamofIhgqtpTlC7CqGLZbFGitLH8fLJ8X+b1yxLVnZhm88GTZaLl",
	"juexZuvurtnde0yAFuNxnC0yUAxtYNCGlUvrVIOOvb4wTmf7SNIFE80GRzz13WRcneI8l/xLGZYXb1/n",
	"eyw/v1o+5Stuj57FLgW+p7WR7E9rgNBmekJp6mzO61fhrVKJCJ3C/BGu79bP75O0k6dGDyvGrLwLhtud",
	"G2YjLQ//vhlbLR2n8l2n0I8rRX+VyJIP1ri7ALcYt4gOnE8uQJVCZLGvpEb+LdBmzULhCUzmuAFQ0u13",
	"fMrbm3zZgZ/MHOd5Yv88h2X+eWhgxkszZkRa67eQ8tWSc8PMywjau1mEmvzGaGyT0flskxpSngxtWjWu",
	"ZLKRSw5m7b7ZHG48BJSkyvwjk8gWvds+nP5XRs9PahuzcemdNpmlKVFr/fUWE2I2KfqMp4/lcAXsqmB+",
	"6ieKZ2DxL5056WpM3IOd7eM67e6/yXR/5fu/6XPfhqf0hpVx908AAAD//0J3mDTxDwAA",
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
