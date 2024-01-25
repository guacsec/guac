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

package guacrest

// commands are split in order to generate code in different files

// server, spec, and types go to generated package
//go:generate go run github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen -generate chi,strict-server -package generated -o generated/server.go openapi.yaml
//go:generate go run github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen -generate spec -package generated -o generated/spec.go openapi.yaml
//go:generate go run github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen -generate types -package generated -o generated/models.go openapi.yaml

// client and types go to client package
//go:generate go run github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen -generate types -package client -o client/models.go openapi.yaml
//go:generate go run github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen -generate client -package client -o client/client.go openapi.yaml
