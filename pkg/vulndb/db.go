package vulndb

import (
	"time"

	"github.com/khulnasoft-lab/tunnel-db/pkg/db"
	"github.com/khulnasoft-lab/tunnel-db/pkg/log"
	"github.com/khulnasoft-lab/tunnel-db/pkg/metadata"
	"github.com/khulnasoft-lab/tunnel-db/pkg/types"
	"github.com/khulnasoft-lab/tunnel-db/pkg/vulnsrc"
	"github.com/khulnasoft-lab/tunnel-db/pkg/vulnsrc/vulnerability"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
	"k8s.io/utils/clock"
)

// VulnDB defines the interface for building vulnerability DBs
type VulnDB interface {
	Build(targets []string) error
}

// TunnelDB represents the vulnerability database engine
type TunnelDB struct {
	dbc            db.Config
	metadata       metadata.Client
	vulnClient     vulnerability.Vulnerability
	vulnSrcs       map[types.SourceID]vulnsrc.VulnSrc
	cacheDir       string
	updateInterval time.Duration
	clock          clock.Clock
}

// Option type allows configuring TunnelDB
type Option func(*TunnelDB)

// WithClock allows using a custom clock (useful for testing)
func WithClock(c clock.Clock) Option {
	return func(t *TunnelDB) {
		t.clock = c
	}
}

// WithVulnSrcs allows overriding vulnerability sources
func WithVulnSrcs(srcs map[types.SourceID]vulnsrc.VulnSrc) Option {
	return func(t *TunnelDB) {
		t.vulnSrcs = srcs
	}
}

// New creates a new TunnelDB instance
func New(cacheDir, outputDir string, updateInterval time.Duration, opts ...Option) *TunnelDB {
	// Initialize vulnerability sources map
	vulnSrcs := map[types.SourceID]vulnsrc.VulnSrc{}
	for _, v := range vulnsrc.All {
		vulnSrcs[v.Name()] = v
	}

	tdb := &TunnelDB{
		dbc:            db.Config{},
		metadata:       metadata.NewClient(outputDir),
		vulnClient:     vulnerability.New(db.Config{}),
		vulnSrcs:       vulnSrcs,
		cacheDir:       cacheDir,
		updateInterval: updateInterval,
		clock:          clock.RealClock{},
	}

	// Apply optional configuration
	for _, opt := range opts {
		opt(tdb)
	}

	return tdb
}

// Insert updates all specified vulnerability sources
func (t *TunnelDB) Insert(targets []string) error {
	log.Info("Updating vulnerability database...")
	eb := oops.In("db")

	for _, target := range targets {
		src, ok := t.vulnSrc(target)
		if !ok {
			return eb.With("target", target).Errorf("target not supported")
		}

		log.WithPrefix(target).Info("Updating data...")
		if err := src.Update(t.cacheDir); err != nil {
			return eb.With("target", target).Wrapf(err, "update error")
		}
	}

	// Update metadata
	md := metadata.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: t.clock.Now().UTC().Add(t.updateInterval),
		UpdatedAt:  t.clock.Now().UTC(),
	}

	if err := t.metadata.Update(md); err != nil {
		return eb.Wrapf(err, "metadata update error")
	}

	return nil
}

// Build runs the complete vulnerability DB build pipeline
func (t *TunnelDB) Build(targets []string) error {
	eb := oops.In("db")

	if err := t.Insert(targets); err != nil {
		return eb.Wrapf(err, "insert error")
	}

	if err := t.optimize(); err != nil {
		return eb.Wrapf(err, "optimize error")
	}

	if err := t.cleanup(); err != nil {
		return eb.Wrapf(err, "cleanup error")
	}

	return nil
}

// vulnSrc returns the VulnSrc for a given target
func (t *TunnelDB) vulnSrc(target string) (vulnsrc.VulnSrc, bool) {
	for _, src := range t.vulnSrcs {
		if target == string(src.Name()) {
			return src, true
		}
	}
	return nil, false
}

// optimize filters and normalizes vulnerabilities
func (t *TunnelDB) optimize() error {
	eb := oops.In("db")

	err := t.dbc.ForEachVulnerabilityID(func(tx *bolt.Tx, cveID string) error {
		eb := eb.With("vuln_id", cveID)
		details := t.vulnClient.GetDetails(cveID)

		if t.vulnClient.IsRejected(details) {
			return nil
		}

		if err := t.dbc.SaveAdvisoryDetails(tx, cveID); err != nil {
			return eb.Wrapf(err, "failed to save advisories")
		}

		if len(details) == 0 {
			return nil
		}

		vuln := t.vulnClient.Normalize(details)
		if err := t.dbc.PutVulnerability(tx, cveID, vuln); err != nil {
			return eb.Wrapf(err, "failed to put vulnerability")
		}

		return nil
	})

	if err != nil {
		return eb.Wrapf(err, "failed to iterate vulnerabilities")
	}

	return nil
}

// cleanup removes temporary buckets used during the build process
func (t *TunnelDB) cleanup() error {
	eb := oops.In("db")

	if err := t.dbc.DeleteVulnerabilityIDBucket(); err != nil {
		return eb.Wrapf(err, "failed to delete vulnerability ID bucket")
	}

	if err := t.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return eb.Wrapf(err, "failed to delete vulnerability detail bucket")
	}

	if err := t.dbc.DeleteAdvisoryDetailBucket(); err != nil {
		return eb.Wrapf(err, "failed to delete advisory detail bucket")
	}

	return nil
}
