package signatures

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"testing"
)

func Test_ecdsaSigner_Sign(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader([]byte("64-characters-deterministic-seed-for-testing-purpose-00000000000")))
	if err != nil {
		panic(err)
	}

	type args struct {
		msg  []byte
		key  interface{}
		opts []SignOption
	}
	tests := []struct {
		name    string
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
				key: &ed25519.PrivateKey{},
			},
			wantErr: true,
		},
		{
			name: "invalid key curve mismatch",
			args: args{
				msg: []byte("test"),
				key: &ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{
						Curve: elliptic.P384(),
					},
				},
			},
			wantErr: true,
		},
		// -----------------------------------------------------
		{
			name: "valid - key pointer",
			args: args{
				msg: []byte("test"),
				key: pk,
			},
			wantErr: false,
		},
		{
			name: "valid - key",
			args: args{
				msg: []byte("test"),
				key: *pk,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ECDSA_P256_SHA256
			_, err := m.Sign(tt.args.msg, tt.args.key, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ecdsaSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_ecdsaSigner_Verify(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader([]byte("64-characters-deterministic-seed-for-testing-purpose-00000000000")))
	if err != nil {
		panic(err)
	}

	type args struct {
		msg       []byte
		signature []byte
		key       interface{}
	}
	tests := []struct {
		name    string
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
				key:       &ed25519.PublicKey{},
			},
			wantErr: true,
		},
		{
			name: "invalid key curve mismatch",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e08b5c84ec2f50ccfef1cb6ca6b5d904eb4b7891b1ef38486f67b7ea4add98a6c6c1180b"),
				key: &ecdsa.PublicKey{
					Curve: elliptic.P384(),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid signature length",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("00"),
				key:       pk.Public(),
			},
			wantErr: true,
		},
		// -----------------------------------------------------
		{
			name: "valid - key pointer",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("35e26737bf72fcf6ef08378b9279431ae6350da9a69f44bf5fe7fa157fd40aec4bde1a16fdf22ac88d8742e163308079e3d2b72173f87a82f4d99fce3476bc65"),
				key:       pk.Public(),
			},
			wantErr: false,
		},
		{
			name: "valid - key",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("35e26737bf72fcf6ef08378b9279431ae6350da9a69f44bf5fe7fa157fd40aec4bde1a16fdf22ac88d8742e163308079e3d2b72173f87a82f4d99fce3476bc65"),
				key: func() ecdsa.PublicKey {
					pub := pk.Public().(*ecdsa.PublicKey)
					return *pub
				}(),
			},
			wantErr: false,
		},
		{
			name: "invalid signature",
			args: args{
				msg:       []byte("test"),
				signature: mustHexDecode("84fdeef9deb4f67a7f73bcd02e6874b4aa1d5891d84fa17830e40804e00000000000000000000000000000000000000000000000000000000000000000000000"),
				key:       pk.Public(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ECDSA_P256_SHA256
			if err := m.Verify(tt.args.msg, tt.args.signature, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("ecdsaSigner.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_ecdsaSigner_Roundtrip(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader([]byte("64-characters-deterministic-seed-for-testing-purpose-00000000000")))
	if err != nil {
		panic(err)
	}
	msg := []byte("test")

	for i := 0; i < 50; i++ {
		sig, err := ECDSA_P256_SHA256.Sign(msg, pk)
		if err != nil {
			panic(err)
		}

		if err := ECDSA_P256_SHA256.Verify(msg, sig, pk.Public()); err != nil {
			panic(err)
		}
	}
}
