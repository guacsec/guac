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
	"strings"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/keyutil"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestFind_OneProvider(t *testing.T) {
	wantKey := setupOneProvider(t)
	tests := []struct {
		name    string
		id      string
		want    crypto.PublicKey
		wantErr bool
	}{{
		name:    "one provider",
		id:      "fake",
		want:    wantKey,
		wantErr: false,
	}, {
		name:    "one provider not found",
		id:      "findme",
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Find(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				err = cryptoutils.EqualKeys(got, tt.want)
				if err != nil {
					t.Errorf("Find() = %v, want %v", got, tt.want)
				}
			}
		})
	}

}

func TestFind_MultiProvider(t *testing.T) {
	wantKey := setupTwoProvider(t)
	tests := []struct {
		name    string
		id      string
		want    crypto.PublicKey
		wantErr bool
	}{{
		name:    "two providers find",
		id:      "fake",
		want:    wantKey[0],
		wantErr: false,
	}, {
		name:    "two provider not found",
		id:      "findme",
		wantErr: true,
	}, {
		name:    "two provider find second item",
		id:      "secondfake",
		want:    wantKey[1],
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Find(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				err = cryptoutils.EqualKeys(got, tt.want)
				if err != nil {
					t.Errorf("Find() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestRetrieve(t *testing.T) {
	wantKey := setupTwoProvider(t)
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
			id:           "fake",
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
			id:           "secondfake",
			providerType: "mock2",
		},
		want:    wantKey[1],
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Retrieve(tt.args.id, tt.args.providerType)
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
				err = cryptoutils.EqualKeys(got, tt.want)
				if err != nil {
					t.Errorf("Find() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestStore(t *testing.T) {
	ecdsaPub := keyutil.GetECDSAPubKey(t)
	rsaPub := keyutil.GetRSAPubKey(t)
	provider := newMockProvider()
	provider2 := newMockProvider()
	RegisterKeyProvider(provider, "mock1")
	RegisterKeyProvider(provider2, "mock2")
	type args struct {
		id           string
		pk           []byte
		providerType KeyProviderType
	}
	tests := []struct {
		name           string
		args           args
		want           crypto.PublicKey
		wantErr        bool
		wantErrMessage string
	}{{
		name: "store in provider 1",
		args: args{
			id:           "fake",
			pk:           keyutil.GetPemBytes(t, ecdsaPub),
			providerType: "mock1",
		},
		want:    ecdsaPub,
		wantErr: false,
	}, {
		name: "store in provider 2",
		args: args{
			id:           "secondfake",
			pk:           keyutil.GetPemBytes(t, rsaPub),
			providerType: "mock2",
		},
		want:    rsaPub,
		wantErr: false,
	}, {
		name: "provider not found",
		args: args{
			id:           "secondfake",
			pk:           keyutil.GetPemBytes(t, rsaPub),
			providerType: "mock3",
		},
		wantErr:        true,
		wantErrMessage: "key provider not initialized for mock3",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Store(tt.args.id, tt.args.pk, tt.args.providerType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Store() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.wantErrMessage) {
					t.Errorf("Retrieve() error = %s, wantErrMessage %s", err, tt.wantErrMessage)
				}
			}
			if err == nil {
				found, _ := Find(tt.args.id)
				err = cryptoutils.EqualKeys(found, tt.want)
				if err != nil {
					t.Errorf("Find() = %v, want %v", found, tt.want)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	provider := newMockProvider()
	provider2 := newMockProvider()
	RegisterKeyProvider(provider, "mock1")
	RegisterKeyProvider(provider2, "mock2")
	provider.collector["fake"] = []byte("fakekey")
	provider2.collector["secondfake"] = []byte("fakesecondkey")
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
			id:           "fake",
			providerType: "mock1",
		},
		wantErr: false,
	}, {
		name: "store in provider 2",
		args: args{
			id:           "secondfake",
			providerType: "mock2",
		},
		wantErr: false,
	}, {
		name: "provider not found",
		args: args{
			id:           "secondfake",
			providerType: "mock3",
		},
		wantErr:        true,
		wantErrMessage: "key provider not initialized for mock3",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Delete(tt.args.id, tt.args.providerType)
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
	collector map[string]crypto.PublicKey
}

func newMockProvider() *mockKeyProvider {
	return &mockKeyProvider{
		collector: map[string]crypto.PublicKey{},
	}
}

func (m *mockKeyProvider) RetrieveKey(id string) (crypto.PublicKey, error) {
	if key, ok := m.collector[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (m *mockKeyProvider) StoreKey(id string, pk crypto.PublicKey) error {
	m.collector[id] = pk
	return nil
}

func (m *mockKeyProvider) DeleteKey(id string) error {
	delete(m.collector, id)
	return nil
}

func (m *mockKeyProvider) Type() KeyProviderType {
	return "mock"
}

func setupOneProvider(t *testing.T) crypto.PublicKey {
	ecdsaPub := keyutil.GetECDSAPubKey(t)
	provider := newMockProvider()
	RegisterKeyProvider(provider, "mock1")
	provider.collector["fake"] = ecdsaPub
	return ecdsaPub
}

func setupTwoProvider(t *testing.T) []crypto.PublicKey {
	ecdsaPub := keyutil.GetECDSAPubKey(t)
	rsaPub := keyutil.GetRSAPubKey(t)
	provider := newMockProvider()
	provider2 := newMockProvider()
	RegisterKeyProvider(provider, "mock1")
	RegisterKeyProvider(provider2, "mock2")
	provider.collector["fake"] = ecdsaPub
	provider2.collector["secondfake"] = rsaPub
	return []crypto.PublicKey{ecdsaPub, rsaPub}
}
