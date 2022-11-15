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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type KeyType string
type KeyScheme string
type KeyProviderType string

const (
	rsaKeyType            KeyType   = "rsa"
	ecdsaKeyType          KeyType   = "ecdsa"
	ed25519KeyType        KeyType   = "ed25519"
	rsassapsssha256Scheme KeyScheme = "rsassa-pss-sha256"
	ecdsaSha2nistp256     KeyScheme = "ecdsa-sha2-nistp256"
	ed25519Scheme         KeyScheme = "ed25519"
)

type KeyProvider interface {
	// RetrieveKey takes in the ID (which is commonly the hash of the key)
	// and it retrieves the wrapped key struct that is associated
	// Returns nil, nil if no keys are found
	// Return nil, error if the request to the provider failed
	RetrieveKey(ctx context.Context, id string) (*Key, error)
	// StoreKey takes in the ID and the crypto.PublicKey and stores them
	// for future retrieval. If key id is already present, it replaces
	// the key with the new one
	StoreKey(ctx context.Context, id string, pk *Key) error
	// DeleteKey takes in the ID and will remove the associated key from the provider
	DeleteKey(ctx context.Context, id string) error
	// Type returns the key provider type
	Type() KeyProviderType
}

type Key struct {
	// Hash sha256 hash of the canonical representation of the key
	Hash string
	// Type represents the type of the key
	Type KeyType
	// Key is the crypto.PublicKey of the public key
	Val crypto.PublicKey
	// Scheme is the supported scheme by the key type.
	Scheme KeyScheme
}

var (
	keyProviders = map[KeyProviderType]KeyProvider{}
)

func RegisterKeyProvider(k KeyProvider, providerType KeyProviderType) error {
	if _, ok := keyProviders[providerType]; ok {
		return fmt.Errorf("the key provider is being overwritten: %s", providerType)
	}
	keyProviders[providerType] = k
	return nil
}

// Find goes through each of the registered key providers and retrieves the wrapped Key
// TODO: Should this handle if multiple keys are returned
func Find(ctx context.Context, id string) (*Key, error) {
	var foundKey *Key
	var err error
	for i := range keyProviders {
		foundKey, err = Retrieve(ctx, id, i)
		if err != nil && !strings.Contains(err.Error(), "failed to find key from key provider") {
			return nil, err
		}
		if foundKey != nil {
			break
		}
	}
	if foundKey == nil {
		return nil, errors.New("failed to find key from key providers")
	}
	return foundKey, nil
}

// Retrieve goes to the specified key provider and gets the wrapped Key
func Retrieve(ctx context.Context, id string, providerType KeyProviderType) (*Key, error) {
	var pubKey *Key
	var err error
	if provider, ok := keyProviders[providerType]; ok {
		pubKey, err = provider.RetrieveKey(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed retrieval of key from %s, with error %w", providerType, err)
		}
	}
	if pubKey == nil {
		return nil, errors.New("failed to find key from key provider")
	}
	return pubKey, nil
}

// Store goes to the specified key provider and stores the wrapped Key.
// It takes in a PEM-encoded byte slice and converts it to a wrapped Key type
// returns a nil error when successful
func Store(ctx context.Context, id string, pemBytes []byte, providerType KeyProviderType) error {
	key, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return err
	}
	keyHash, err := dsse.SHA256KeyID(key)
	if err != nil {
		return err
	}
	keyType, KeyScheme, err := getKeyInfo(key)
	if err != nil {
		return err
	}
	foundKey := &Key{
		Hash:   keyHash,
		Type:   keyType,
		Val:    key,
		Scheme: KeyScheme,
	}
	if provider, ok := keyProviders[providerType]; ok {
		err := provider.StoreKey(ctx, id, foundKey)
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
func Delete(ctx context.Context, id string, providerType KeyProviderType) error {
	if provider, ok := keyProviders[providerType]; ok {
		err := provider.DeleteKey(ctx, id)
		if err != nil {
			return fmt.Errorf("failed deleting of key from %s, with error %w", providerType, err)
		}
	} else {
		return fmt.Errorf("key provider not initialized for %s", providerType)
	}
	return nil
}

func getKeyInfo(pub crypto.PublicKey) (KeyType, KeyScheme, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return rsaKeyType, rsassapsssha256Scheme, nil
	case *ecdsa.PublicKey:
		return ecdsaKeyType, ecdsaSha2nistp256, nil
	// ed25519 is not using a pointer here due to its implementation. Using a pointer
	// will result in the case statement failing to find the ed25519 key type
	case ed25519.PublicKey:
		return ed25519KeyType, ed25519Scheme, nil
	default:
		return "", "", errors.New("unsupported key type")
	}
}
