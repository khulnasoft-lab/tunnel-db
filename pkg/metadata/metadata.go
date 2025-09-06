package metadata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/oops"
)

const metadataFile = "metadata.json"

// Metadata stores the state of the database
type Metadata struct {
	Version      int       `json:",omitempty"`
	NextUpdate   time.Time
	UpdatedAt    time.Time
	DownloadedAt time.Time // Filled after downloading
}

// Client manages metadata file operations
type Client struct {
	filePath string
}

// NewClient creates a new metadata Client for the given database directory
func NewClient(dbDir string) *Client {
	return &Client{
		filePath: Path(dbDir),
	}
}

// Path returns the full path to the metadata file
func Path(dbDir string) string {
	return filepath.Join(dbDir, metadataFile)
}

// Get reads the metadata from the file
func (c *Client) Get() (Metadata, error) {
	eb := oops.With("file_path", c.filePath)

	f, err := os.Open(c.filePath)
	if err != nil {
		return Metadata{}, eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	var meta Metadata
	if err = json.NewDecoder(f).Decode(&meta); err != nil {
		return Metadata{}, eb.Wrapf(err, "json decode error")
	}
	return meta, nil
}

// Update writes the metadata to the file, creating directories as needed
func (c *Client) Update(meta Metadata) error {
	eb := oops.With("file_path", c.filePath)

	if err := os.MkdirAll(filepath.Dir(c.filePath), 0o744); err != nil {
		return eb.Wrapf(err, "mkdir error")
	}

	f, err := os.Create(c.filePath)
	if err != nil {
		return eb.Wrapf(err, "file create error")
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(&meta); err != nil {
		return eb.Wrapf(err, "json encode error")
	}

	return nil
}

// Delete removes the metadata file
func (c *Client) Delete() error {
	if err := os.Remove(c.filePath); err != nil {
		return oops.With("file_path", c.filePath).Wrapf(err, "file remove error")
	}
	return nil
}
