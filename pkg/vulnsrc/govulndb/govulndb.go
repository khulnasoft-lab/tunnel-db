package govulndb

import (
	"encoding/json"
	"path/filepath"

	"go.khulnasoft.com/tunnel-db/pkg/types"
	"go.khulnasoft.com/tunnel-db/pkg/vulnsrc/osv"
	"go.khulnasoft.com/tunnel-db/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const sourceID = vulnerability.GoVulnDB

var osvDir = filepath.Join("govulndb", "data", "osv")

type DatabaseSpecific struct {
	URL string `json:"url"`
}

type VulnDB struct{}

func NewVulnSrc() VulnDB {
	return VulnDB{}
}

func (VulnDB) Name() types.SourceID {
	return sourceID
}

func (VulnDB) Update(root string) error {
	dataSources := map[types.Ecosystem]types.DataSource{
		vulnerability.Go: {
			ID:   sourceID,
			Name: "The Go Vulnerability Database",
			URL:  "https://pkg.go.dev/vuln/",
		},
	}

	return osv.New(osvDir, sourceID, dataSources, &transformer{}).Update(root)
}

type transformer struct{}

func (t *transformer) TransformAdvisories(advisories []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var specific DatabaseSpecific
	if err := json.Unmarshal(entry.DatabaseSpecific, &specific); err != nil {
		return nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	var filtered []osv.Advisory
	for _, adv := range advisories {
		// Insert only stdlib advisories
		if adv.PkgName != "stdlib" {
			continue
		}
		// Add a reference
		if specific.URL != "" {
			adv.References = append(adv.References, specific.URL)
		}
		filtered = append(filtered, adv)
	}

	return filtered, nil
}