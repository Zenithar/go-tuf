package key_test

import (
	"crypto/ed25519"
	"reflect"
	"testing"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/key"
)

func TestFromPrivateKey(t *testing.T) {
	largeBuffer := make([]byte, key.MaxKeyInputSize+1)

	type args struct {
		tufPk *data.PrivateKey
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
			name: "empty",
			args: args{
				tufPk: &data.PrivateKey{},
			},
			wantErr: true,
		},
		{
			name: "too-large",
			args: args{
				tufPk: &data.PrivateKey{
					Type:  data.KeyTypeEd25519,
					Value: largeBuffer,
				},
			},
			wantErr: true,
		},
		{
			name: "valid - ed25519 public",
			args: args{
				tufPk: &data.PrivateKey{
					Type:  data.KeyTypeEd25519,
					Value: []byte(`{"public":"lYlkLRyJC0UuPECEqqGUBaDHj8qJ+GLjZs7TRwKhGcY="}`),
				},
			},
			wantErr: false,
			want: ed25519.PublicKey([]byte{
				0x95, 0x89, 0x64, 0x2d, 0x1c, 0x89, 0x0b, 0x45,
				0x2e, 0x3c, 0x40, 0x84, 0xaa, 0xa1, 0x94, 0x05,
				0xa0, 0xc7, 0x8f, 0xca, 0x89, 0xf8, 0x62, 0xe3,
				0x66, 0xce, 0xd3, 0x47, 0x02, 0xa1, 0x19, 0xc6,
			}),
		},
		{
			name: "valid - ed25519 private",
			args: args{
				tufPk: &data.PrivateKey{
					Type:  data.KeyTypeEd25519,
					Value: []byte(`{"public":"lYlkLRyJC0UuPECEqqGUBaDHj8qJ+GLjZs7TRwKhGcY=","private":"MzItY2hhcmFjdGVycy1kZXRlcm1pbmlzdGljLXNlZWSViWQtHIkLRS48QISqoZQFoMePyon4YuNmztNHAqEZxg=="}`),
				},
			},
			wantErr: false,
			want: ed25519.PrivateKey([]byte{
				0x33, 0x32, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x61,
				0x63, 0x74, 0x65, 0x72, 0x73, 0x2d, 0x64, 0x65,
				0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x69, 0x73,
				0x74, 0x69, 0x63, 0x2d, 0x73, 0x65, 0x65, 0x64,
				0x95, 0x89, 0x64, 0x2d, 0x1c, 0x89, 0x0b, 0x45,
				0x2e, 0x3c, 0x40, 0x84, 0xaa, 0xa1, 0x94, 0x05,
				0xa0, 0xc7, 0x8f, 0xca, 0x89, 0xf8, 0x62, 0xe3,
				0x66, 0xce, 0xd3, 0x47, 0x02, 0xa1, 0x19, 0xc6,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := key.FromPrivateKey(tt.args.tufPk)
			if (err != nil) != tt.wantErr {
				t.Errorf("key.FromPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("key.FromPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
