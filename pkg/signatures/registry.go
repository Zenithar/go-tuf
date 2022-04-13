package signatures

import (
	"crypto"
	"sync"

	// Load crypto algorithms
	_ "crypto/sha256"
)

var registry = sync.Map{}

// Builder defines signer algorithm implementation builder contract.
type Builder func() Algorithm

// RegisterAlgorithm in the signer implementation registry.
func RegisterAlgorithm(name string, b Builder) {
	registry.Store(name, b)
}

// GetAlgorithm returns a signer instance or nil if name doesn't match.
func GetAlgorithm(name string) (alg Algorithm) {
	if bRaw, ok := registry.Load(name); ok {
		if b, ok := bRaw.(Builder); ok {
			return b()
		}
	}

	// No builder found
	return nil
}

// GetAlgorithms retuns the registered signer names.
func GetAlgorithms() (names []string) {
	registry.Range(func(key, value interface{}) bool {
		names = append(names, key.(string))
		return true
	})

	return names
}

var (
	Ed25519           Algorithm
	ECDSA_P256_SHA256 Algorithm
	ECDSA_P384_SHA384 Algorithm
)

func init() {
	// Ed25519
	Ed25519 = &ed25519Signer{}
	RegisterAlgorithm(Ed25519.Name(), func() Algorithm { return Ed25519 })

	// ECDSA Algorithms
	ECDSA_P256_SHA256 = &ecdsaSigner{name: "ecdsa-sha2-nistp256", hash: crypto.SHA256, keySize: 32, curveBits: 256}
	RegisterAlgorithm(ECDSA_P256_SHA256.Name(), func() Algorithm { return ECDSA_P256_SHA256 })
	ECDSA_P384_SHA384 = &ecdsaSigner{name: "ecdsa-sha384-nistp384", hash: crypto.SHA384, keySize: 48, curveBits: 384}
	RegisterAlgorithm(ECDSA_P384_SHA384.Name(), func() Algorithm { return ECDSA_P384_SHA384 })
}
