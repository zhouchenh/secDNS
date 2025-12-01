package core

import (
	"github.com/zhouchenh/secDNS/internal/common"
	"os"
	"path/filepath"
	"runtime"
)

var (
	name    = "secDNS"
	version = "1.3.0"
	build   = ""
	intro   = "A DNS Resolver with custom rules."
)

func Name() string {
	return name
}

func Version() string {
	return version
}

func VersionStatement() []string {
	return []string{
		common.Concatenate(Name(), " ", Version(), " ", build, "(", runtime.GOOS, "/", runtime.GOARCH, ")"),
		intro,
	}
}

func EnvKey(key ...interface{}) string {
	var args []interface{}
	args = append(args, Name())
	args = append(args, key...)
	return common.UpperString(common.SnakeCaseConcatenate(args...))
}

func OpenFile(path string) (*os.File, error) {
	if file, err := os.Open(path); err == nil {
		return file, err
	} else {
		if env := os.Getenv(EnvKey("config", "dir", "path")); env != "" {
			if file, err := os.Open(filepath.Join(env, path)); err == nil {
				return file, err
			}
		}
		return nil, err
	}
}
