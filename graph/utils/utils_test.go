package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var getProcessedTableNameTests = []struct {
	env       string
	envVal    string
	tableName string
	expected  string
	ok        bool
}{
	{"TABLE_SUFFIX_GOTEST", "dev", "gotest-test1", "gotest-dev-test1", true},
	{"TABLE_SUFFIX_GOTEST", "dev", "gotest1-test1", "gotest1-test1", true},
	{"TABLE_SUFFIX_ZEETEST", "prod", "zeetest-test1", "zeetest-prod-test1", true},
	{"TABLE_SUFFIX_ZEETEST", "prod", "zeetest-test1", "zeetest-dev-test1", false},
}

func TestGetProcessedTableName(t *testing.T) {
	// add environment variable TABLE_SUFFIX_GOTEST to the environment
	// to test the table name
	for _, tt := range getProcessedTableNameTests {
		os.Setenv(tt.env, tt.envVal)
		actual := GetProcessedTableName(tt.tableName)
		require.Equal(t, tt.ok, tt.expected == actual)
	}
}
