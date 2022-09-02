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

package key

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sirupsen/logrus"
)

type KeyProvider interface {
	// RetrieveKey takes in the ID (which is commonly the hash of the key)
	// and it retrieves the crypto.PublicKey that is associated
	// Returns nil, nil if no keys are found
	// Return nil, error if the request to the provider failed
	RetrieveKey(id string) (crypto.PublicKey, error)
	// StoreKey takes in the ID and the crypto.PublicKey and stores them
	// for future retrieval. If key id is already present, it replaces
	// the key with the new one
	StoreKey(id string, pk crypto.PublicKey) error
	// DeleteKey takes in the ID and will remove the associated key from the provider
	DeleteKey(id string) error
	// Type returns the key provider type
	Type() KeyProviderType
}

type KeyProviderType string

var (
	keyProviders = map[KeyProviderType]KeyProvider{}
)

func RegisterKeyProvider(k KeyProvider, providerType KeyProviderType) {
	if _, ok := keyProviders[providerType]; ok {
		logrus.Warnf("the key provider is being overwritten: %s", providerType)
	}
	keyProviders[providerType] = k
}

// Find goes through each of the registered key providers and retrieves the key
// TODO: Should this handle if multiple keys are returned
func Find(id string) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	var err error
	for i, keyProvider := range keyProviders {
		key, err = keyProvider.RetrieveKey(id)
		if err != nil {
			return nil, fmt.Errorf("failed retrieval of key from %s, with error %w", i, err)
		}
		if key != nil {
			break
		}
	}
	if key == nil {
		return nil, errors.New("failed to find key from key providers")
	}
	return key, nil
}

// Retrieve goes to the specified key provider and gets the key
func Retrieve(id string, providerType KeyProviderType) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	var err error
	if provider, ok := keyProviders[providerType]; ok {
		key, err = provider.RetrieveKey(id)
		if err != nil {
			return nil, fmt.Errorf("failed retrieval of key from %s, with error %w", providerType, err)
		}
	}
	if key == nil {
		return nil, errors.New("failed to find key from key provider")
	}
	return key, nil
}

// Store goes to the specified key provider and stores the Key
// takes in a PEM-encoded byte slice and converts it to a crypto.PublicKey
// returns a nil error when successful
func Store(id string, pemBytes []byte, providerType KeyProviderType) error {
	key, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return err
	}
	if provider, ok := keyProviders[providerType]; ok {
		err := provider.StoreKey(id, key)
		if err != nil {
			return fmt.Errorf("failed storing of key to %s, with error %w", providerType, err)
		}
	} else {
		return fmt.Errorf("key provider not initialized for %s", providerType)
	}
	return nil
}

// Delete goes to the specified key provider and deletes the Key
// returns a nil error when successful
func Delete(id string, providerType KeyProviderType) error {
	if provider, ok := keyProviders[providerType]; ok {
		err := provider.DeleteKey(id)
		if err != nil {
			return fmt.Errorf("failed deleting of key from %s, with error %w", providerType, err)
		}
	} else {
		return fmt.Errorf("key provider not initialized for %s", providerType)
	}
	return nil
}
