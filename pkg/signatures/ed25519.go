package signatures

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

type ed25519Signer struct{}

// Compile time assertion to ensure Algoritm contract.
var _ Algorithm = (*ed25519Signer)(nil)

func (m *ed25519Signer) Name() string {
	return "ed25519"
}

// Compile time assertion to ensure Signer contract.
var _ Signer = (*ed25519Signer)(nil)

func (m *ed25519Signer) Sign(msg []byte, key interface{}, opts ...SignOption) ([]byte, error) {
	// Check arguments
	switch {
	case len(msg) == 0:
		return nil, fmt.Errorf("ed25519: provided msg is nil or empty: %w", ErrInvalidArgument)
	case key == nil:
		return nil, fmt.Errorf("ed25519: provided key is nil: %w", ErrInvalidKey)
	}

	// Check key type
	var (
		pk ed25519.PrivateKey
	)
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		pk = *k
	case ed25519.PrivateKey:
		pk = k
	default:
		return nil, fmt.Errorf("ed25519: unsupported private key type (%T): %w", key, ErrInvalidKey)
	}

	// Check key length
	if len(pk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: invalid key size: %w", ErrInvalidKey)
	}

	// Prepare default settings
	dopts := &SignOptions{
		randSource: rand.Reader,
	}

	// Apply functional options
	for _, o := range opts {
		o(dopts)
	}

	// Sign with the key
	sig, err := pk.Sign(dopts.randSource, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ed25519: unable to sign payload: %w", err)
	}

	// No error
	return sig, nil
}

// Compile time assertion to ensure Verifier contract.
var _ Verifier = (*ed25519Signer)(nil)

// Verify the given msg and signature match.
func (m *ed25519Signer) Verify(msg, signature []byte, key interface{}) error {
	// Check arguments
	switch {
	case len(msg) == 0:
		return fmt.Errorf("ed25519: provided msg is nil or empty: %w", ErrInvalidArgument)
	case len(signature) == 0:
		return fmt.Errorf("ed25519: provided signature is nil or empty: %w", ErrInvalidArgument)
	case key == nil:
		return fmt.Errorf("ed25519: provided key is nil: %w", ErrInvalidKey)
	}

	// Check key type
	var (
		pub ed25519.PublicKey
	)
	switch k := key.(type) {
	case *ed25519.PublicKey:
		pub = *k
	case ed25519.PublicKey:
		pub = k
	default:
		return fmt.Errorf("ed25519: unsupported public key type (%T): %w", key, ErrInvalidKey)
	}

	// Check key length
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519: invalid key size: %w", ErrInvalidKey)
	}

	// Validate the signature
	if ok := ed25519.Verify(pub, msg, signature); !ok {
		return ErrInvalidSignature
	}

	// No error
	return nil
}
