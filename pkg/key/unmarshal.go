package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/theupdateframework/go-tuf/data"
)

const (
	// MaxKeyInputSize defines the maximum processing length.
	MaxKeyInputSize = 1024 * 1024 // 1Mb
)

func FromPrivateKey(tufPk *data.PrivateKey) (interface{}, error) {
	// Check arguments
	if tufPk == nil {
		return nil, errors.New("key: invalid private key object")
	}

	// Try to decode the json value.
	var key jsonKeyPair
	if err := json.NewDecoder(io.LimitReader(bytes.NewReader(tufPk.Value), MaxKeyInputSize)).Decode(&key); err != nil {
		return nil, fmt.Errorf("key: unable to decode the key components: %w", err)
	}

	// Select appropriate decoding strategy
	switch tufPk.Type {
	case data.KeyTypeEd25519:
		return unmarshalEd25519Key(&key)
	case data.KeyTypeECDSA_SHA2_P256:
		return unmarshalECDSAKey(&key)
	case data.KeyTypeRSASSA_PSS_SHA256:
		return unmarshalRSAKey(&key)
	}

	// Default to error
	return nil, fmt.Errorf("key: unsupported private key type %q", tufPk.Type)
}

func FromPublicKey(tufPk *data.PublicKey) (interface{}, error) {
	// Check arguments
	if tufPk == nil {
		return nil, errors.New("key: invalid public key object")
	}

	// Try to decode the json value.
	var key jsonKeyPair
	if err := json.NewDecoder(io.LimitReader(bytes.NewReader(tufPk.Value), MaxKeyInputSize)).Decode(&key); err != nil {
		return nil, fmt.Errorf("key: unable to decode the key components: %w", err)
	}

	// Select appropriate decoding strategy
	switch tufPk.Type {
	case data.KeyTypeEd25519:
		return unmarshalEd25519Key(&key)
	case data.KeyTypeECDSA_SHA2_P256:
		return unmarshalECDSAKey(&key)
	case data.KeyTypeRSASSA_PSS_SHA256:
		return unmarshalRSAKey(&key)
	}

	// Default to error
	return nil, fmt.Errorf("key: unsupported public key type %q", tufPk.Type)
}

// ----------------------------------------------------------------------------

type jsonKeyPair struct {
	Public  []byte  `json:"public"`
	Private *[]byte `json:"private,omitempty"`
}

// ----------------------------------------------------------------------------

func unmarshalEd25519Key(raw *jsonKeyPair) (interface{}, error) {
	// Check arguments
	if raw == nil {
		return nil, errors.New("key: nil decoded key components")
	}

	// Validate public key length
	if len(raw.Public) != ed25519.PublicKeySize {
		return nil, errors.New("key: unexpected public key length for ed25519 key")
	}

	// Check for low order public key
	if isEdLowOrder(raw.Public) {
		return nil, errors.New("key: the public key is blacklisted")
	}

	// Check private key
	if raw.Private == nil {
		return ed25519.PublicKey(raw.Public), nil
	}

	// Validate private key length
	if len(*raw.Private) != ed25519.PrivateKeySize {
		return nil, errors.New("key: unexpected public key length for ed25519 key")
	}

	// Generate public key from private key
	pub, _, err := ed25519.GenerateKey(bytes.NewReader(*raw.Private))
	if err != nil {
		return nil, fmt.Errorf("key: unable to derive public key from private key: %w", err)
	}

	// Compare keys
	if subtle.ConstantTimeCompare(raw.Public, pub) != 1 {
		return nil, errors.New("key: public and private keys doesn't match")
	}

	return ed25519.PrivateKey(*raw.Private), nil
}

func unmarshalECDSAKey(raw *jsonKeyPair) (interface{}, error) {
	// Check arguments
	if raw == nil {
		return nil, errors.New("key: nil decoded key components")
	}

	// TUF only support P-256 curve
	curve := elliptic.P256()

	// Get expected length
	byteSize := curveByteSize(curve.Params())

	if len(raw.Public) < 1 {
		return nil, errors.New("key: invalid public key size")
	}

	var (
		x, y *big.Int
	)
	// Select unmarshalling according to data first byte
	switch raw.Public[0] {
	case 2, 3:
		x, y = elliptic.UnmarshalCompressed(curve, raw.Public)
	case 4:
		x, y = elliptic.Unmarshal(curve, raw.Public)
	default:
		return nil, errors.New("key: unsupported ecdsa public key encoding")
	}
	if x == nil {
		return nil, errors.New("key: unable to decode ecdsa public key")
	}

	// Check point
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("key: ecdsa public key point is not on the associated curve")
	}

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// No private key defined
	if raw.Private == nil {
		// Return public key
		return &pub, nil
	}

	// Check private key length
	if len(*raw.Private) != byteSize {
		return nil, errors.New("key: invalid ecdsa private key length for the associated curve")
	}

	// Load private key
	d := big.NewInt(0).SetBytes(*raw.Private)

	// Compute public key
	dx, dy := curve.ScalarBaseMult(*raw.Private)
	if dx.Cmp(pub.X) != 0 || dy.Cmp(pub.Y) != 0 {
		return nil, errors.New("key: public and private keys doesn't match")
	}

	// Return private key
	return &ecdsa.PrivateKey{
		PublicKey: pub,
		D:         d,
	}, nil
}

func unmarshalRSAKey(raw *jsonKeyPair) (interface{}, error) {
	// Check arguments
	if raw == nil {
		return nil, errors.New("key: nil decoded key components")
	}

	return nil, nil
}

func curveByteSize(params *elliptic.CurveParams) int {
	bitSize := params.BitSize
	byteSize := bitSize / 8
	if bitSize%8 != 0 {
		byteSize++
	}
	return byteSize
}
