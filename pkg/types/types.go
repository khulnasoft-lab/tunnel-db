package types

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity represents the level of a vulnerability.
type Severity int

// VendorSeverity maps a SourceID to its severity.
type VendorSeverity map[SourceID]Severity

// CVSS represents CVSS scores and vectors for multiple versions.
type CVSS struct {
	V2Vector  string  `json:"V2Vector,omitempty"`
	V3Vector  string  `json:"V3Vector,omitempty"`
	V40Vector string  `json:"V40Vector,omitempty"`
	V2Score   float64 `json:"V2Score,omitempty"`
	V3Score   float64 `json:"V3Score,omitempty"`
	V40Score  float64 `json:"V40Score,omitempty"`
}

// CVSSVector holds simple v2/v3 vector representation.
type CVSSVector struct {
	V2 string `json:"v2,omitempty"`
	V3 string `json:"v3,omitempty"`
}

// VendorCVSS maps SourceID to CVSS data.
type VendorCVSS map[SourceID]CVSS

// Severity constants
const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var SeverityNames = []string{
	"UNKNOWN",
	"LOW",
	"MEDIUM",
	"HIGH",
	"CRITICAL",
}

// NewSeverity converts a string to a Severity value.
func NewSeverity(severity string) (Severity, error) {
	for i, name := range SeverityNames {
		if severity == name {
			return Severity(i), nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity: %s", severity)
}

// CompareSeverityString returns an integer difference of two severity strings.
func CompareSeverityString(sev1, sev2 string) int {
	s1, _ := NewSeverity(sev1)
	s2, _ := NewSeverity(sev2)
	return int(s2) - int(s1)
}

// String converts Severity to string.
func (s Severity) String() string {
	return SeverityNames[s]
}

// LastUpdated represents a timestamp of last update.
type LastUpdated struct {
	Date time.Time
}

// VulnerabilityDetail holds detailed info for a single vulnerability.
type VulnerabilityDetail struct {
	ID               string     `json:",omitempty"`
	CvssScore        float64    `json:",omitempty"`
	CvssVector       string     `json:",omitempty"`
	CvssScoreV3      float64    `json:",omitempty"`
	CvssVectorV3     string     `json:",omitempty"`
	CvssScoreV40     float64    `json:",omitempty"`
	CvssVectorV40    string     `json:",omitempty"`
	Severity         Severity   `json:",omitempty"`
	SeverityV3       Severity   `json:",omitempty"`
	SeverityV40      Severity   `json:",omitempty"`
	CweIDs           []string   `json:",omitempty"`
	References       []string   `json:",omitempty"`
	Title            string     `json:",omitempty"`
	Description      string     `json:",omitempty"`
	PublishedDate    *time.Time `json:",omitempty"`
	LastModifiedDate *time.Time `json:",omitempty"`
}

// AdvisoryDetail holds advisory info per platform/package
type AdvisoryDetail struct {
	PlatformName string
	PackageName  string
	AdvisoryItem interface{}
}

// SourceID represents the ID of a data source (e.g., NVD)
type SourceID string

// DataSource represents metadata about an advisory source.
type DataSource struct {
	ID     SourceID `json:",omitempty"`
	Name   string   `json:",omitempty"`
	URL    string   `json:",omitempty"`
	BaseID SourceID `json:",omitempty"` // Base source (optional)
}

// Status represents advisory status (internal use)
type Status int

// Advisory represents a vulnerability advisory for a package
type Advisory struct {
	VulnerabilityID    string     `json:",omitempty"`
	VendorIDs          []string   `json:",omitempty"`
	Arches             []string   `json:",omitempty"`
	Status             Status     `json:"-"`
	Severity           Severity   `json:",omitempty"`
	FixedVersion       string     `json:",omitempty"`
	AffectedVersion    string     `json:",omitempty"`
	VulnerableVersions []string   `json:",omitempty"`
	PatchedVersions    []string   `json:",omitempty"`
	UnaffectedVersions []string   `json:",omitempty"`
	DataSource         *DataSource `json:",omitempty"`
	Custom             interface{} `json:",omitempty"`
}

// _Advisory is an internal struct to avoid infinite MarshalJSON recursion
type _Advisory Advisory

// dbAdvisory is used for custom JSON marshaling
type dbAdvisory struct {
	_Advisory
	IntStatus int `json:"Status,omitempty"`
}

// MarshalJSON encodes Advisory with Status as int to reduce DB size
func (a *Advisory) MarshalJSON() ([]byte, error) {
	return json.Marshal(dbAdvisory{
		_Advisory: _Advisory(*a),
		IntStatus: int(a.Status),
	})
}

// UnmarshalJSON decodes Advisory from DB JSON
func (a *Advisory) UnmarshalJSON(data []byte) error {
	var advisory dbAdvisory
	if err := json.Unmarshal(data, &advisory); err != nil {
		return err
	}
	advisory._Advisory.Status = Status(advisory.IntStatus)
	*a = Advisory(advisory._Advisory)
	return nil
}

// Advisories holds multiple advisory entries for a package
type Advisories struct {
	FixedVersion string     `json:",omitempty"`
	Entries      []Advisory `json:",omitempty"`
	Custom       interface{} `json:",omitempty"`
}

// Vulnerability is a normalized view of a vulnerability
type Vulnerability struct {
	Title            string         `json:",omitempty"`
	Description      string         `json:",omitempty"`
	Severity         string         `json:",omitempty"`
	CweIDs           []string       `json:",omitempty"`
	VendorSeverity   VendorSeverity `json:",omitempty"`
	CVSS             VendorCVSS     `json:",omitempty"`
	References       []string       `json:",omitempty"`
	PublishedDate    *time.Time     `json:",omitempty"`
	LastModifiedDate *time.Time     `json:",omitempty"`
	Custom           interface{}    `json:",omitempty"`
}

// Ecosystem represents a language-specific ecosystem
type Ecosystem string
