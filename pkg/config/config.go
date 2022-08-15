//
// Copyright 2021 The AFF Authors.
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

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	cm "knative.dev/pkg/configmap"
)

type Config struct {
	Storage StorageConfigs
}

// StorageConfigs contains the configuration to instantiate different storage providers
type StorageConfigs struct {
	GCS          GCSStorageConfig
	OCI          OCIStorageConfig
	Transparency TransparencyConfig
	PubSub       PubSubStorageConfig
}

type GCSStorageConfig struct {
	Bucket string
}

type OCIStorageConfig struct {
	Repository string
	Insecure   bool
}

type PubSubStorageConfig struct {
	Provider string
	Topic    string
	Kafka    KafkaStorageConfig
}

type KafkaStorageConfig struct {
	BootstrapServers string
}

type TransparencyConfig struct {
	Enabled          bool
	VerifyAnnotation bool
	URL              string
}

const (
	gcsBucketKey             = "storage.gcs.bucket"
	ociRepositoryKey         = "storage.oci.repository"
	ociRepositoryInsecureKey = "storage.oci.repository.insecure"

	// PubSub - General
	pubsubProvider = "storage.pubsub.provider"
	pubsubTopic    = "storage.pubsub.topic"

	// No config for PubSub - In-Memory

	// PubSub - Kafka
	pubsubKafkaBootstrapServer = "storage.pubsub.kafka.bootstrap.servers"

	transparencyEnabledKey = "transparency.enabled"
	transparencyURLKey     = "transparency.url"
)

func defaultConfig() *Config {
	return &Config{
		Storage: StorageConfigs{
			GCS: GCSStorageConfig{
				Bucket: "URL",
			},
			OCI: OCIStorageConfig{
				Repository: "URL",
				Insecure:   false,
			},
			Transparency: TransparencyConfig{
				URL: "https://rekor.sigstore.dev",
			},
		},
	}
}

// NewConfigFromMap creates a Config from the supplied map
func NewConfigFromMap(data map[string]string) (*Config, error) {
	cfg := defaultConfig()

	if err := cm.Parse(data,
		// PubSub - General
		asString(pubsubProvider, &cfg.Storage.PubSub.Provider, "inmemory", "kafka"),
		asString(pubsubTopic, &cfg.Storage.PubSub.Topic),

		// PubSub - Kafka
		asString(pubsubKafkaBootstrapServer, &cfg.Storage.PubSub.Kafka.BootstrapServers),

		// Storage level configs
		asString(gcsBucketKey, &cfg.Storage.GCS.Bucket),
		asString(ociRepositoryKey, &cfg.Storage.OCI.Repository),
		asBool(ociRepositoryInsecureKey, &cfg.Storage.OCI.Insecure),

		oneOf(transparencyEnabledKey, &cfg.Storage.Transparency.Enabled, "true"),
		asString(transparencyURLKey, &cfg.Storage.Transparency.URL),
	); err != nil {
		return nil, fmt.Errorf("failed to parse data: %w", err)
	}

	return cfg, nil
}

// NewConfigFromConfigMap creates a Config from the supplied ConfigMap
func NewConfigFromConfigMap(configMap *corev1.ConfigMap) (*Config, error) {
	return NewConfigFromMap(configMap.Data)
}

// oneOf sets target to true if it maches any of the values
func oneOf(key string, target *bool, values ...string) cm.ParseFunc {
	return func(data map[string]string) error {
		raw, ok := data[key]
		if !ok {
			return nil
		}
		if values == nil {
			return nil
		}
		for _, v := range values {
			if v == raw {
				*target = true
			}
		}
		return nil
	}
}

// allow additional supported values for a "true" decision
// in additional to the usual ones provided by strconv.ParseBool
func asBool(key string, target *bool) cm.ParseFunc {
	return func(data map[string]string) error {
		raw, ok := data[key]
		if !ok {
			return nil
		}
		val, err := strconv.ParseBool(raw)
		if err == nil {
			*target = val
			return nil
		}
		return nil
	}
}

// asString passes the value at key through into the target, if it exists.
// TODO(mattmoor): This might be a nice variation on cm.AsString to upstream.
func asString(key string, target *string, values ...string) cm.ParseFunc {
	return func(data map[string]string) error {
		raw, ok := data[key]
		if !ok {
			return nil
		}
		if len(values) > 0 {
			vals := sets.NewString(values...)
			if !vals.Has(raw) {
				return fmt.Errorf("invalid value %q wanted one of %v", raw, vals.List())
			}
		}
		*target = raw
		return nil
	}
}

// asStringSet parses the value at key as a sets.String (split by ',') into the target, if it exists.
func asStringSet(key string, target *sets.String, allowed sets.String) cm.ParseFunc {
	return func(data map[string]string) error {
		if raw, ok := data[key]; ok {
			if raw == "" {
				*target = sets.NewString("")
				return nil
			}
			splitted := strings.Split(raw, ",")
			if allowed.Len() > 0 {
				for i, v := range splitted {
					splitted[i] = strings.TrimSpace(v)
					if !allowed.Has(splitted[i]) {
						return fmt.Errorf("invalid value %q wanted one of %v", splitted[i], allowed.List())
					}
				}
			}
			*target = sets.NewString(splitted...)
		}
		return nil
	}
}
