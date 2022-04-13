package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func Test_unmarshalEd25519Key(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader([]byte("32-characters-deterministic-seed")))
	pub2, _, _ := ed25519.GenerateKey(bytes.NewReader([]byte("other-seed-for-deterministic-key")))

	fmt.Printf("%x\n", pub)
	fmt.Printf("%x\n", priv)

	type args struct {
		raw *jsonKeyPair
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank",
			args: args{
				raw: &jsonKeyPair{
					Public: []byte(""),
				},
			},
			wantErr: true,
		},
		{
			name: "public key too short",
			args: args{
				raw: &jsonKeyPair{
					Public: []byte("000000000"),
				},
			},
			wantErr: true,
		},
		{
			name: "private key too short",
			args: args{
				raw: &jsonKeyPair{
					Public: pub2,
					Private: func() *[]byte {
						raw := []byte("")
						return &raw
					}(),
				},
			},
			wantErr: true,
		},
		{
			name: "public / private mismatch",
			args: args{
				raw: &jsonKeyPair{
					Public: pub2,
					Private: func() *[]byte {
						raw := []byte(priv)
						return &raw
					}(),
				},
			},
			wantErr: true,
		},
		{
			name: "valid - public",
			args: args{
				raw: &jsonKeyPair{
					Public: pub,
				},
			},
			wantErr: false,
			want:    pub,
		},
		{
			name: "valid - private",
			args: args{
				raw: &jsonKeyPair{
					Public: pub,
					Private: func() *[]byte {
						raw := []byte(priv)
						return &raw
					}(),
				},
			},
			wantErr: false,
			want:    priv,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalEd25519Key(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("unmarshalEd25519Key() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalEd25519Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_unmarshalECDSAKey(t *testing.T) {
	priv, x, y, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	point := elliptic.Marshal(elliptic.P256(), x, y)
	compressedPoint := elliptic.MarshalCompressed(elliptic.P256(), x, y)

	type args struct {
		raw *jsonKeyPair
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank",
			args: args{
				raw: &jsonKeyPair{
					Public: []byte(""),
				},
			},
			wantErr: true,
		},
		{
			name: "point",
			args: args{
				raw: &jsonKeyPair{
					Public: point,
				},
			},
			wantErr: false,
			want: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		},
		{
			name: "compressed point",
			args: args{
				raw: &jsonKeyPair{
					Public: compressedPoint,
				},
			},
			wantErr: false,
			want: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		},
		{
			name: "private",
			args: args{
				raw: &jsonKeyPair{
					Public:  compressedPoint,
					Private: &priv,
				},
			},
			wantErr: false,
			want: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     x,
					Y:     y,
				},
				D: big.NewInt(0).SetBytes(priv),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalECDSAKey(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("unmarshalECDSAKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalECDSAKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
