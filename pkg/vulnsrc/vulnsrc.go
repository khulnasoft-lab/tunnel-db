package vulnsrc

import (
	"github.com/khulnasoft/tunnel-db/pkg/types"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/alma"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/alpine"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/amazon"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/aqua"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/azure"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/bitnami"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/bundler"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/chainguard"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/composer"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/debian"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/ghsa"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/glad"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/govulndb"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/k8svulndb"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/node"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/khulnasoft/tunnel-db/pkg/vulnsrc/oracle-oval"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/photon"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/khulnasoft/tunnel-db/pkg/vulnsrc/redhat-oval"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/rocky"
	susecvrf "github.com/khulnasoft/tunnel-db/pkg/vulnsrc/suse-cvrf"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/ubuntu"
	"github.com/khulnasoft/tunnel-db/pkg/vulnsrc/wolfi"
)

type VulnSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []VulnSrc{
		// NVD
		nvd.NewVulnSrc(),

		// OS packages
		alma.NewVulnSrc(),
		alpine.NewVulnSrc(),
		redhat.NewVulnSrc(),
		redhatoval.NewVulnSrc(),
		debian.NewVulnSrc(),
		ubuntu.NewVulnSrc(),
		amazon.NewVulnSrc(),
		oracleoval.NewVulnSrc(),
		rocky.NewVulnSrc(),
		susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		photon.NewVulnSrc(),
		azure.NewVulnSrc(azure.Azure),
		azure.NewVulnSrc(azure.Mariner),
		wolfi.NewVulnSrc(),
		chainguard.NewVulnSrc(),
		bitnami.NewVulnSrc(),

		k8svulndb.NewVulnSrc(),

		// Language-specific packages
		bundler.NewVulnSrc(),
		composer.NewVulnSrc(),
		node.NewVulnSrc(),
		ghsa.NewVulnSrc(),
		glad.NewVulnSrc(),
		govulndb.NewVulnSrc(), // For Go stdlib packages

		aqua.NewVulnSrc(),
	}
)
