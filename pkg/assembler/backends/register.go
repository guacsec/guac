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

package backends

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
)

type GBFunc func(context.Context, BackendArgs) (Backend, error)
type FlagRegistrarFunc func(*cobra.Command) error
type FlagParserFunc func(ctx context.Context) (BackendArgs, error)

var (
	getBackend    map[string]GBFunc
	flagRegistrar map[string]FlagRegistrarFunc
	flagParser    map[string]FlagParserFunc
)

func init() {
	getBackend = make(map[string]GBFunc)
	flagRegistrar = make(map[string]FlagRegistrarFunc)
	flagParser = make(map[string]FlagParserFunc)
}

// Register registers a backend with its flag handling functions
func Register(name string, gb GBFunc, fr FlagRegistrarFunc, fp FlagParserFunc) {
	getBackend[name] = gb
	flagRegistrar[name] = fr
	flagParser[name] = fp
}

// RegisterFlags registers all backend-specific flags to the given command
func RegisterFlags(cmd *cobra.Command) error {
	var err error
	for _, register := range flagRegistrar {
		err = register(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetBackendArgs returns the parsed backend arguments for the given backend
func GetBackendArgs(ctx context.Context, name string) (BackendArgs, error) {
	if parser, ok := flagParser[name]; ok {
		return parser(ctx)
	}
	return nil, fmt.Errorf("backend %s not found", name)
}

func Get(name string, ctx context.Context, args BackendArgs) (Backend, error) {
	return getBackend[name](ctx, args)
}

func List() []string {
	return maps.Keys(getBackend)
}
