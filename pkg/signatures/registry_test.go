package signatures

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_registry_All(t *testing.T) {
	names := GetAlgorithms()
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			// Resolve with name
			algorithm := GetAlgorithm(name)
			assert.NotNil(t, algorithm, "Registered name %q returned a nil implementation", name)
			assert.Equal(t, name, algorithm.Name())
		})
	}
}

func Test_registry_Unknown(t *testing.T) {
	algorithm := GetAlgorithm("not-existent")
	assert.Nil(t, algorithm)
}
