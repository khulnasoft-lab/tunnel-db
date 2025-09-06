package vulnsrctest

import (
	"sort"
	"testing"

	"github.com/khulnasoft-lab/tunnel-db/pkg/db"
	"github.com/khulnasoft-lab/tunnel-db/pkg/dbtest"
	"github.com/khulnasoft-lab/tunnel-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Updater defines an interface for vulnerability sources that can be updated.
type Updater interface {
	Update(dir string) error
}

// WantValues represents expected key/value pairs for database tests.
type WantValues struct {
	Key   []string
	Value interface{}
}

// TestUpdateArgs holds arguments and expectations for TestUpdate.
type TestUpdateArgs struct {
	Dir        string
	WantValues []WantValues
	WantErr    string
	NoBuckets  [][]string
}

// TestUpdate runs a standard update test for a vulnerability source.
func TestUpdate(t *testing.T, vulnsrc Updater, args TestUpdateArgs) {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := db.Path(tempDir)

	require.NoError(t, db.Init(tempDir))
	defer db.Close()

	err := vulnsrc.Update(args.Dir)
	if args.WantErr != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), args.WantErr)
		return
	}
	require.NoError(t, err)

	// Close DB before checking JSON values
	require.NoError(t, db.Close())

	for _, want := range args.WantValues {
		dbtest.JSONEq(t, dbPath, want.Key, want.Value, want.Key)
	}

	for _, noBucket := range args.NoBuckets {
		dbtest.NoBucket(t, dbPath, noBucket, noBucket)
	}
}

// Getter defines an interface for retrieving advisories from a vulnerability source.
type Getter interface {
	Get(release, pkgName string) ([]types.Advisory, error)
}

// TestGetArgs holds arguments and expectations for TestGet.
type TestGetArgs struct {
	Fixtures   []string
	WantValues []types.Advisory
	Release    string
	PkgName    string
	WantErr    string
}

// TestGet runs a standard retrieval test for a vulnerability source.
func TestGet(t *testing.T, vulnsrc Getter, args TestGetArgs) {
	t.Helper()

	_ = dbtest.InitDB(t, args.Fixtures)
	defer db.Close()

	got, err := vulnsrc.Get(args.Release, args.PkgName)

	if args.WantErr != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), args.WantErr)
		return
	}

	require.NoError(t, err)

	// Sort results for deterministic comparison
	sort.Slice(got, func(i, j int) bool {
		return got[i].VulnerabilityID < got[j].VulnerabilityID
	})

	assert.Equal(t, args.WantValues, got)
}
