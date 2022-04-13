package signatures

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

func mustHexDecode(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}

	return out
}

func Test_ed25519Signer_Sign(t *testing.T) {
	pk := ed25519.NewKeyFromSeed([]byte("32-characters-deterministic-seed"))

	type args struct {
		msg  []byte
		key  interface{}
		opts []SignOption
	}
	tests := []struct {
		name    string
		m       *ed25519Signer
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "invalid args: nil message",
			args: args{
				msg: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid args: blank message",
			args: args{
				msg: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "invalid args: nil key",
			args: args{
				msg: []byte("test"),
				key: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid key type",
			args: args{
				msg: []byte("test"),
				key: &ecdsa.PrivateKey{},
			},
			wantErr: true,
		},
		{
			name: "invalid key size",
			args: args{
				msg: []byte("test"),
				key: ed25519.PrivateKey([]byte("")),
			},
			wantErr: true,
		},
		// -----------------------------------------------------
		{
			name: "valid - key",
			args: args{
				msg: []byte("test"),
				key: pk,
			},
			wantErr: false,
			want:    mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
		},
		{
			name: "valid - key pointer",
			args: args{
				msg: []byte("test"),
				key: &pk,
			},
			wantErr: false,
			want:    mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
		},
		{
			name: "valid - key pointer with random source",
			args: args{
				msg: []byte("test"),
				key: &pk,
				opts: []SignOption{
					withSignRandomSource(rand.Reader),
				},
			},
			wantErr: false,
			want:    mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ed25519Signer{}
			got, err := m.Sign(tt.args.msg, tt.args.key, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ed25519Signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ed25519Signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ed25519Signer_Verify(t *testing.T) {
	pk := ed25519.NewKeyFromSeed([]byte("32-characters-deterministic-seed"))

	type args struct {
		msg       []byte
		signature []byte
		key       interface{}
	}
	tests := []struct {
		name    string
		m       *ed25519Signer
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "invalid args: nil message",
			args: args{
				msg: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid args: blank message",
			args: args{
				msg: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "invalid args: nil signature",
			args: args{
				msg:       []byte("test"),
				signature: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid args: blank signature",
			args: args{
				msg:       []byte("test"),
				signature: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "invalid args: nil key",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
				key:       nil,
			},
			wantErr: true,
		},
		{
			name: "invalid key type",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
				key:       &ecdsa.PublicKey{},
			},
			wantErr: true,
		},
		{
			name: "invalid key size",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
				key:       &ed25519.PublicKey{},
			},
			wantErr: true,
		},
		// -----------------------------------------------------
		{
			name: "valid - key",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
				key:       pk.Public(),
			},
			wantErr: false,
		},
		{
			name: "valid - key pointer",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
				key: func() *ed25519.PublicKey {
					pub := pk.Public().(ed25519.PublicKey)
					return &pub
				}(),
			},
			wantErr: false,
		},
		{
			name: "invalid signature",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e00000000000000000000000000000000000000000000000000000000000000000000000"),
				key: func() *ed25519.PublicKey {
					pub := pk.Public().(ed25519.PublicKey)
					return &pub
				}(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ed25519Signer{}
			if err := m.Verify(tt.args.msg, tt.args.signature, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("ed25519Signer.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_ed25519Signer_Roundtrip(t *testing.T) {
	pk := ed25519.NewKeyFromSeed([]byte("32-characters-deterministic-seed"))
	msg := []byte("test")

	for i := 0; i < 50; i++ {
		sig, err := Ed25519.Sign(msg, pk)
		if err != nil {
			panic(err)
		}

		if err := Ed25519.Verify(msg, sig, pk.Public()); err != nil {
			panic(err)
		}
	}
}
