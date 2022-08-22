//
// Copyright 2022 The AFF Authors.
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

package config

type Config struct {
	Collector CollectorConfigs
}

// CollectorConfigs contains the configuration to instantiate different collector providers
type CollectorConfigs struct {
	GCS          GCSSCollectorConfig
	OCI          OCICollectorConfig
	Transparency TransparencyConfig
	PubSub       PubSubCollectorConfig
}

type GCSSCollectorConfig struct {
	Bucket string
}

type OCICollectorConfig struct {
	Repository string
	Insecure   bool
}

type PubSubCollectorConfig struct {
	Provider string
	Topic    string
}

type TransparencyConfig struct {
	Enabled          bool
	VerifyAnnotation bool
	URL              string
}
