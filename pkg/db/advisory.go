package db

import (
	"encoding/json"

	"github.com/khulnasoft-lab/tunnel-db/pkg/types"
	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
)

func (dbc Config) PutAdvisory(tx *bolt.Tx, bktNames []string, key string, advisory any) error {
	if err := dbc.put(tx, bktNames, key, advisory); err != nil {
		return oops.With("key", key).Wrapf(err, "failed to put advisory")
	}
	return nil
}

func (dbc Config) ForEachAdvisory(sources []string, pkgName string) (map[string]Value, error) {
	return dbc.forEach(append(sources, pkgName))
}

func (dbc Config) GetAdvisories(source, pkgName string) ([]types.Advisory, error) {
	eb := oops.With("source", source).With("package_name", pkgName)
	advisories, err := dbc.ForEachAdvisory([]string{source}, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "advisory foreach error")
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []types.Advisory
	for vulnID, v := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(v.Content, &advisory); err != nil {
			return nil, eb.With("vuln_id", vulnID).Wrapf(err, "json unmarshal error")
		}

		advisory.VulnerabilityID = vulnID
		if !lo.IsEmpty(v.Source) {
			advisory.DataSource = &types.DataSource{
				ID:     v.Source.ID,
				Name:   v.Source.Name,
				URL:    v.Source.URL,
				BaseID: v.Source.BaseID,
			}
		}

		results = append(results, advisory)
	}
	return results, nil
}

// CreateIndexes creates indexes on key fields for advisories
func (dbc Config) CreateIndexes(tx *bolt.Tx) error {
	// Example: Create an index on the "advisory" bucket
	advisoryBucket := tx.Bucket([]byte("advisory"))
	if advisoryBucket == nil {
		return oops.Errorf("advisory bucket not found")
	}

	// Create an index on the "vulnID" field
	err := advisoryBucket.ForEach(func(k, v []byte) error {
		var advisory map[string]interface{}
		if err := json.Unmarshal(v, &advisory); err != nil {
			return oops.Wrapf(err, "json unmarshal error")
		}

		indexKey := []byte(advisory["vulnID"].(string) + ":" + string(k))
		return advisoryBucket.Put(indexKey, v)
	})
	if err != nil {
		return oops.Wrapf(err, "failed to create index on vulnID")
	}

	return nil
}
