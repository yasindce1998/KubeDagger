package assets

import (
	"embed"
	"fmt"
)

//go:embed bin/bootstrap.o
var bootstrapBytes []byte

//go:embed bin/main.o
var mainBytes []byte

func Asset(name string) ([]byte, error) {
	switch name {
	case "/bootstrap.o", "bootstrap.o":
		return bootstrapBytes, nil
	case "/main.o", "main.o":
		return mainBytes, nil
	default:
		return nil, fmt.Errorf("asset not found: %s", name)
	}
}

func MustAsset(name string) []byte {
	b, err := Asset(name)
	if err != nil {
		panic(err)
	}
	return b
}

// AssetNames returns the list of available asset names.
func AssetNames() []string {
	return []string{"bootstrap.o", "main.o"}
}

// Embedded provides direct access to the embedded filesystem.
var Embedded embed.FS
