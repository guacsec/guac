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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sirupsen/logrus"
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

func RegisterKeyProvider(k KeyProvider, providerType KeyProviderType) {
	if _, ok := keyProviders[providerType]; ok {
		logrus.Warnf("the key provider is being overwritten: %s", providerType)
	}
	keyProviders[providerType] = k
}

// Find goes through each of the registered key providers and retrieves the key
// TODO: Should this handle if multiple keys are returned
func Find(id string) (*Key, error) {
	var foundKey *Key
	var err error
	for i := range keyProviders {
		foundKey, err = Retrieve(id, i)
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

// Retrieve goes to the specified key provider and gets the key
func Retrieve(id string, providerType KeyProviderType) (*Key, error) {
	var pubKey crypto.PublicKey
	var err error
	if provider, ok := keyProviders[providerType]; ok {
		pubKey, err = provider.RetrieveKey(id)
		if err != nil {
			return nil, fmt.Errorf("failed retrieval of key from %s, with error %w", providerType, err)
		}
	}
	if pubKey == nil {
		return nil, errors.New("failed to find key from key provider")
	}
	keyHash, err := getKeyHash(pubKey)
	if err != nil {
		return nil, err
	}
	keyType, KeyScheme, err := getKeyInfo(pubKey)
	if err != nil {
		return nil, err
	}
	foundKey := &Key{
		Hash:   keyHash,
		Type:   keyType,
		Val:    pubKey,
		Scheme: KeyScheme,
	}
	return foundKey, nil
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

func getKeyHash(pub crypto.PublicKey) (string, error) {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return "", fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
	}
	keyObj, err := x509.NewPublicKey(bytes.NewReader(pemBytes))
	if err != nil {
		return "", err
	}

	canonKey, err := keyObj.CanonicalValue()
	if err != nil {
		return "", fmt.Errorf("could not canonicize key: %w", err)
	}

	keyHash := sha256.Sum256(canonKey)
	return "sha256:" + hex.EncodeToString(keyHash[:]), nil

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
