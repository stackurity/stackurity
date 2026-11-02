package main

import (
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/plugins"
)

// The server accepts the metadata (field limits, required lists).
func TestMetadataAccepted(t *testing.T) {
	m := azurePlugin{}.Metadata()
	m.ProtocolVersion, m.SchemaVersion = "1", model.BatchSchemaVersion
	if err := plugins.CheckMetadata(&m); err != nil {
		t.Fatal(err)
	}
}
