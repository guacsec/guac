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
	"reflect"
	"strings"
	"testing"

	"github.com/guacsec/guac/internal/testing/keyutil"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func TestFind_OneProvider(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider, _, wantKey := setupOneProvider(t)
	provider.collector["ecdsa"] = wantKey
	tests := []struct {
		name    string
		id      string
		want    *Key
		wantErr bool
	}{{
		name:    "one provider",
		id:      "ecdsa",
		want:    wantKey,
		wantErr: false,
	}, {
		name:    "one provider not found",
		id:      "findme",
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Find(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("DSSEProcessor.Unpack() = %v, expected %v", got, tt.want)
				}
			}
		})
	}

}

func TestFind_MultiProvider(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider, _, wantKey := setupTwoProvider(t)
	provider[0].collector["ecdsa"] = wantKey[0]
	provider[1].collector["rsa"] = wantKey[1]
	tests := []struct {
		name    string
		id      string
		want    *Key
		wantErr bool
	}{{
		name:    "two providers find",
		id:      "ecdsa",
		want:    wantKey[0],
		wantErr: false,
	}, {
		name:    "two provider not found",
		id:      "findme",
		wantErr: true,
	}, {
		name:    "two provider find second item",
		id:      "rsa",
		want:    wantKey[1],
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Find(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("DSSEProcessor.Unpack() = %v, expected %v", got, tt.want)
				}
			}
		})
	}
}

func TestRetrieve(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider, _, wantKey := setupTwoProvider(t)
	provider[0].collector["ecdsa"] = wantKey[0]
	provider[1].collector["rsa"] = wantKey[1]
	type args struct {
		id           string
		providerType KeyProviderType
	}
	tests := []struct {
		name           string
		args           args
		want           crypto.PublicKey
		wantErr        bool
		wantErrMessage string
	}{{
		name: "one provider",
		args: args{
			id:           "ecdsa",
			providerType: "mock1",
		},
		want:    wantKey[0],
		wantErr: false,
	}, {
		name: "not found",
		args: args{
			id:           "findme",
			providerType: "mock1",
		},
		wantErr:        true,
		wantErrMessage: "failed to find key from key provider",
	}, {
		name: "provider not found",
		args: args{
			id:           "findme",
			providerType: "mock",
		},
		wantErr:        true,
		wantErrMessage: "failed to find key from key provider",
	}, {
		name: "two provider",
		args: args{
			id:           "rsa",
			providerType: "mock2",
		},
		want:    wantKey[1],
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Retrieve(ctx, tt.args.id, tt.args.providerType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.wantErrMessage) {
					t.Errorf("Retrieve() error = %s, wantErrMessage %s", err, tt.wantErrMessage)
				}
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("DSSEProcessor.Unpack() = %v, expected %v", got, tt.want)
				}
			}
		})
	}
}

func TestStore(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	_, pubBytes, wantKey := setupTwoProvider(t)
	type args struct {
		id           string
		pk           []byte
		providerType KeyProviderType
	}
	tests := []struct {
		name           string
		args           args
		want           *Key
		wantErr        bool
		wantErrMessage string
	}{{
		name: "store in provider 1",
		args: args{
			id:           "ecdsa",
			pk:           pubBytes[0],
			providerType: "mock1",
		},
		want:    wantKey[0],
		wantErr: false,
	}, {
		name: "store in provider 2",
		args: args{
			id:           "rsa",
			pk:           pubBytes[1],
			providerType: "mock2",
		},
		want:    wantKey[1],
		wantErr: false,
	}, {
		name: "provider not found",
		args: args{
			id:           "rsa",
			pk:           pubBytes[1],
			providerType: "mock3",
		},
		wantErr:        true,
		wantErrMessage: "key provider not initialized for mock3",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Store(ctx, tt.args.id, tt.args.pk, tt.args.providerType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Store() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.wantErrMessage) {
					t.Errorf("Retrieve() error = %s, wantErrMessage %s", err, tt.wantErrMessage)
				}
			} else {
				found, _ := Find(ctx, tt.args.id)
				if !reflect.DeepEqual(found, tt.want) {
					t.Errorf("DSSEProcessor.Unpack() = %v, expected %v", found, tt.want)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider := newMockProvider()
	provider2 := newMockProvider()
	err := RegisterKeyProvider(provider, "mock4")
	if err != nil {
		t.Log(err)
	}
	err = RegisterKeyProvider(provider2, "mock5")
	if err != nil {
		t.Log(err)
	}
	provider.collector["ecdsa"] = &Key{
		Type: "ecdsa",
	}
	provider2.collector["rsa"] = &Key{
		Type: "rsa",
	}
	type args struct {
		id           string
		providerType KeyProviderType
	}
	tests := []struct {
		name           string
		args           args
		wantErr        bool
		wantErrMessage string
	}{{
		name: "delete in provider 1",
		args: args{
			id:           "ecdsa",
			providerType: "mock4",
		},
		wantErr: false,
	}, {
		name: "delete in provider 2",
		args: args{
			id:           "rsa",
			providerType: "mock5",
		},
		wantErr: false,
	}, {
		name: "provider not found",
		args: args{
			id:           "rsa",
			providerType: "mock6",
		},
		wantErr:        true,
		wantErrMessage: "key provider not initialized for mock6",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Delete(ctx, tt.args.id, tt.args.providerType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.wantErrMessage) {
					t.Errorf("Retrieve() error = %s, wantErrMessage %s", err, tt.wantErrMessage)
				}
			}
			if tt.args.providerType == "mock1" {
				if _, found := provider.collector[tt.args.id]; found {
					t.Errorf("Delete() failed as key still found")
				}
			} else if tt.args.providerType == "mock2" {
				if _, found := provider2.collector[tt.args.id]; found {
					t.Errorf("Delete() failed as key still found")
				}
			}
		})
	}
}

type mockKeyProvider struct {
	collector map[string]*Key
}

func newMockProvider() *mockKeyProvider {
	return &mockKeyProvider{
		collector: map[string]*Key{},
	}
}

func (m *mockKeyProvider) RetrieveKey(ctx context.Context, id string) (*Key, error) {
	if key, ok := m.collector[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (m *mockKeyProvider) StoreKey(ctx context.Context, id string, pk *Key) error {
	m.collector[id] = pk
	return nil
}

func (m *mockKeyProvider) DeleteKey(ctx context.Context, id string) error {
	delete(m.collector, id)
	return nil
}

func (m *mockKeyProvider) Type() KeyProviderType {
	return "mock"
}

func setupOneProvider(t *testing.T) (*mockKeyProvider, []byte, *Key) {
	ecdsaPub, ecdsaPem, err := keyutil.GetECDSAPubKey()
	if err != nil {
		t.Fatalf("failed to get ecdsa key. Error: %v", err)
	}
	provider := newMockProvider()
	err = RegisterKeyProvider(provider, "mock1")
	if err != nil {
		t.Log(err)
	}
	keyHash, err := dsse.SHA256KeyID(ecdsaPub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	keyType, KeyScheme, err := getKeyInfo(ecdsaPub)

	if err != nil {
		t.Fatal("failed to get key type and scheme for test")
	}
	foundKey := &Key{
		Hash:   keyHash,
		Type:   keyType,
		Val:    ecdsaPub,
		Scheme: KeyScheme,
	}
	return provider, ecdsaPem, foundKey
}

func setupTwoProvider(t *testing.T) ([]*mockKeyProvider, [][]byte, []*Key) {
	ecdsaPub, ecdsaPem, err := keyutil.GetECDSAPubKey()
	if err != nil {
		t.Fatalf("failed to get ecdsa key. Error: %v", err)
	}
	rsaPub, rsaPem, err := keyutil.GetRSAPubKey()
	if err != nil {
		t.Fatalf("failed to get rsa key. Error: %v", err)
	}

	ed25519Pub, ed25519Pem, err := keyutil.GetED25519Pub()
	if err != nil {
		t.Fatalf("failed to get ed25519 key. Error: %v", err)
	}

	var provider *mockKeyProvider
	var provider2 *mockKeyProvider

	if foundProvider, ok := keyProviders["mock1"]; ok {
		provider = foundProvider.(*mockKeyProvider)
	} else {
		provider = newMockProvider()
		err = RegisterKeyProvider(provider, "mock1")
		if err != nil {
			t.Log(err)
		}
	}

	if foundProvider, ok := keyProviders["mock2"]; ok {
		provider2 = foundProvider.(*mockKeyProvider)
	} else {
		provider2 = newMockProvider()
		err = RegisterKeyProvider(provider2, "mock2")
		if err != nil {
			t.Log(err)
		}
	}

	keyHash, err := dsse.SHA256KeyID(ecdsaPub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	keyType, KeyScheme, err := getKeyInfo(ecdsaPub)

	if err != nil {
		t.Fatal("failed to get key type and scheme for test")
	}
	ecdsaKey := &Key{
		Hash:   keyHash,
		Type:   keyType,
		Val:    ecdsaPub,
		Scheme: KeyScheme,
	}

	keyHash, err = dsse.SHA256KeyID(rsaPub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	keyType, KeyScheme, err = getKeyInfo(rsaPub)
	if err != nil {
		t.Fatal("failed to get key type and scheme for test")
	}
	rsaKey := &Key{
		Hash:   keyHash,
		Type:   keyType,
		Val:    rsaPub,
		Scheme: KeyScheme,
	}

	keyHash, err = dsse.SHA256KeyID(ed25519Pub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	keyType, KeyScheme, err = getKeyInfo(ed25519Pub)

	if err != nil {
		t.Fatal("failed to get key type and scheme for test")
	}
	ed25519Key := &Key{
		Hash:   keyHash,
		Type:   keyType,
		Val:    ed25519Pub,
		Scheme: KeyScheme,
	}

	return []*mockKeyProvider{provider, provider2}, [][]byte{ecdsaPem, rsaPem, ed25519Pem}, []*Key{ecdsaKey, rsaKey, ed25519Key}
}
