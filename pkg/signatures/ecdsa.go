package signatures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
)

type ecdsaSigner struct {
	name      string
	hash      crypto.Hash
	curveBits int
	keySize   int
}

// Compile time assertion to ensure Algoritm contract.
var _ Algorithm = (*ecdsaSigner)(nil)

func (m *ecdsaSigner) Name() string {
	return m.name
}

// Compile time assertion to ensure Signer contract.
var _ Signer = (*ecdsaSigner)(nil)

func (m *ecdsaSigner) Sign(msg []byte, key interface{}, opts ...SignOption) ([]byte, error) {
	// Check arguments
	switch {
	case len(msg) == 0:
		return nil, fmt.Errorf("ecdsa: provided msg is nil or empty: %w", ErrInvalidArgument)
	case key == nil:
		return nil, fmt.Errorf("ecdsa: provided key is nil: %w", ErrInvalidKey)
	}

	// Check key type
	var (
		pk *ecdsa.PrivateKey
	)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pk = k
	case ecdsa.PrivateKey:
		pk = &k
	default:
		return nil, fmt.Errorf("ecdsa: unsupported private key type (%T): %w", key, ErrInvalidKey)
	}

	// Check the key and signer curve size match.
	curveBits := pk.Curve.Params().BitSize
	if m.curveBits != curveBits {
		return nil, fmt.Errorf("ecdsa: can't use the provided key with this signer instance, curve mismatch: %w", ErrInvalidKey)
	}

	// Prepare default settings
	dopts := &SignOptions{
		randSource: rand.Reader,
	}

	// Apply functional options
	for _, o := range opts {
		o(dopts)
	}

	// Create the hasher
	if !m.hash.Available() {
		return nil, ErrHashUnavailable
	}

	// Create protected content hash
	hasher := m.hash.New()
	if _, err := hasher.Write(msg); err != nil {
		return nil, fmt.Errorf("ecdsa: unable to compute protected content hash: %w", err)
	}

	// Sign the string and return r, s
	if r, s, err := ecdsa.Sign(dopts.randSource, pk, hasher.Sum(nil)); err == nil {
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		// We serialize the outputs (r and s) into big-endian byte arrays
		// padded with zeros on the left to make sure the sizes work out.
		// Output must be 2*keyBytes long.
		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
		s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

		// No error
		return out, nil
	}

	// Default to invalid signature error
	return nil, ErrInvalidSignature
}

// Compile time assertion to ensure Verifier contract.
var _ Verifier = (*ecdsaSigner)(nil)

// Verify the given msg and signature match.
func (m *ecdsaSigner) Verify(msg, signature []byte, key interface{}) error {
	// Check arguments
	switch {
	case len(msg) == 0:
		return fmt.Errorf("ecdsa: provided msg is nil or empty: %w", ErrInvalidArgument)
	case len(signature) == 0:
		return fmt.Errorf("ecdsa: provided signature is nil or empty: %w", ErrInvalidArgument)
	case key == nil:
		return fmt.Errorf("ecdsa: provided key is nil: %w", ErrInvalidKey)
	}

	// Check key type
	var (
		pub *ecdsa.PublicKey
	)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		pub = k
	case ecdsa.PublicKey:
		pub = &k
	default:
		return fmt.Errorf("ecdsa: unsupported public key type (%T): %w", key, ErrInvalidKey)
	}

	// Check the key and signer curve size match.
	curveBits := pub.Curve.Params().BitSize
	if m.curveBits != curveBits {
		return fmt.Errorf("ecdsa: can't use the provided key with this signer instance, curve mismatch: %w", ErrInvalidKey)
	}

	// Validate signature size
	if len(signature) != 2*m.keySize {
		return fmt.Errorf("ecdsa: invalid signature length: %w", ErrInvalidSignature)
	}

	// Extract components
	r := big.NewInt(0).SetBytes(signature[:m.keySize])
	s := big.NewInt(0).SetBytes(signature[m.keySize:])

	// Create the hasher
	if !m.hash.Available() {
		return ErrHashUnavailable
	}

	// Create protected content hash
	hasher := m.hash.New()
	if _, err := hasher.Write(msg); err != nil {
		return fmt.Errorf("ecdsa: unable to compute protected content hash: %w", err)
	}

	// Verify the signature
	if ok := ecdsa.Verify(pub, hasher.Sum(nil), r, s); ok {
		// No error
		return nil
	}

	// Default to error
	return ErrInvalidSignature
}
