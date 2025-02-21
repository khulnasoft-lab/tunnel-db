package db

import (
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
)

// GenerateSchemaOverview generates an overview of all tables, relations, and key fields
func (dbc Config) GenerateSchemaOverview() (string, error) {
	var overview strings.Builder

	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			overview.WriteString("Bucket: " + string(name) + "\n")
			return b.ForEach(func(k, v []byte) error {
				overview.WriteString("  Key: " + string(k) + "\n")
				return nil
			})
		})
	})
	if err != nil {
		return "", oops.Wrapf(err, "failed to generate schema overview")
	}

	return overview.String(), nil
}
