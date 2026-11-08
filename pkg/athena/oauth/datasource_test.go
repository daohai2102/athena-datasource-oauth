// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// Unit tests for downstream OAuth datasource wrapper and query argument injection.
// =========================================================================

package oauth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInjectOAuthHashIntoQueryJSON(t *testing.T) {
	t.Run("returns empty if input is empty", func(t *testing.T) {
		res := InjectOAuthHashIntoQueryJSON(nil, "abc123hash")
		assert.Nil(t, res)
	})

	t.Run("injects __oauth_hash into existing connectionArgs", func(t *testing.T) {
		input := json.RawMessage(`{"region":"us-east-1","connectionArgs":{"catalog":"AwsDataCatalog"}}`)
		output := InjectOAuthHashIntoQueryJSON(input, "hash-123456")

		var m map[string]any
		err := json.Unmarshal(output, &m)
		require.NoError(t, err)

		connArgs, ok := m["connectionArgs"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "AwsDataCatalog", connArgs["catalog"])
		assert.Equal(t, "hash-123456", connArgs["__oauth_hash"])
	})

	t.Run("creates connectionArgs if absent", func(t *testing.T) {
		input := json.RawMessage(`{"rawSQL":"SELECT 1"}`)
		output := InjectOAuthHashIntoQueryJSON(input, "hash-999999")

		var m map[string]any
		err := json.Unmarshal(output, &m)
		require.NoError(t, err)

		connArgs, ok := m["connectionArgs"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "hash-999999", connArgs["__oauth_hash"])
	})
}
