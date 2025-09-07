package db_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/khulnasoft-lab/tunnel-db/pkg/db"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name   string
		dbPath string
		dbOpts *bbolt.Options
	}{
		{
			name:   "normal db",
			dbPath: "testdata/normal.db",
		},
		{
			name:   "broken db",
			dbPath: "testdata/broken.db",
		},
		{
			name:   "no db",
			dbPath: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tt.dbPath != "" {
				dbPath := db.Path(tmpDir)
				dbDir := filepath.Dir(dbPath)
				err := os.MkdirAll(dbDir, 0o700)
				require.NoError(t, err)

				err = copyFile(dbPath, tt.dbPath)
				require.NoError(t, err)
			}

			err := db.Init(tmpDir, db.WithBoltOptions(tt.dbOpts))
			require.NoError(t, err)
		})
	}
}

func copyFile(dstPath, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, src)
	return err
}

func TestConfig_CreateIndexes(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		wantErr  string
	}{
		{
			name:     "create indexes on all key fields",
			fixtures: []string{"testdata/fixtures/advisory-detail.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB for testing
			dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			err := dbc.BatchUpdate(func(tx *bolt.Tx) error {
				return dbc.CreateIndexes(tx)
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestConfig_GenerateSchemaOverview(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		want     string
		wantErr  string
	}{
		{
			name:     "generate schema overview",
			fixtures: []string{"testdata/fixtures/advisory-detail.yaml"},
			want: `Bucket: advisory-detail
  Key: CVE-2019-14904
  Key: CVE-2020-1234
Bucket: vulnerability-detail
  Key: CVE-2019-14904
  Key: CVE-2020-1234
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB for testing
			dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			got, err := dbc.GenerateSchemaOverview()

			if tt.wantErr != "" {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
