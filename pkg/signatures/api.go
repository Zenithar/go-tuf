package signatures

import (
	"errors"
	"io"
)

// Signer represents signature producer contract.
type Signer interface {
	// Sign the given msg with the given key.
	Sign(msg []byte, key interface{}, opts ...SignOption) ([]byte, error)
}

// Verifier represents signature verifier contract.
type Verifier interface {
	// Verify the given msg and signature match.
	Verify(msg, signature []byte, key interface{}) error
}

type Algorithm interface {
	Signer
	Verifier

	// Name returns the implementation name of the algorithm.
	Name() string
}

var (
	// ErrInvalidKey is raised when the given key is nil or unsupported
	// by the implementation.
	ErrInvalidKey = errors.New("signer: invalid or unsupported key format")

	// ErrInvalidArgument is raised when something prevent or make one of
	// operation argument validation to fail.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrHashUnavailable is raised when trying to build a hash function when
	// the implementation is not loaded or available.
	ErrHashUnavailable = errors.New("the required hash function is not available")

	// ErrInvalidSignature is raised when something prevent or make the
	// signature verification to fail.
	ErrInvalidSignature = errors.New("invalid signature")
)

// -------------------------------------------------------------

// SignOptions defines the signing operation options.
type SignOptions struct {
	// Randomness source used by signer implementation.
	randSource io.Reader
}

// SigningOption defines signing operations optional parameters.
type SignOption func(*SignOptions)

// withSignRandomSource sets the randomness source.
func withSignRandomSource(r io.Reader) SignOption {
	return func(o *SignOptions) {
		o.randSource = r
	}
}
