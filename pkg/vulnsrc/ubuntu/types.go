package ubuntu

type UbuntuCVE struct {
	Description string `json:"description"`
	Candidate   string
	Priority    string
	Patches     map[PackageName]Patch
	References  []string
	PublicDate  string // for extensibility, not used in tunnel-db
}

type (
	PackageName string
	Release     string
	Patch       map[Release]Status
)

type Status struct {
	Status string
	Note   string
}
