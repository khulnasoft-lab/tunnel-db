package azure

import "github.com/khulnasoft-lab/tunnel-db/pkg/vulnsrc/azure/oval"

type operator string

type Entry struct {
	PkgName  string
	Version  string
	Operator operator
	Metadata oval.Metadata
}
