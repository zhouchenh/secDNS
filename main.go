package main

import (
	"flag"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/config"
	"github.com/zhouchenh/secDNS/internal/core"
	_ "github.com/zhouchenh/secDNS/internal/features"
	"os"
	"path/filepath"
	"runtime"
)

var (
	configFilePath = flag.String("config", "", "Specify a config file")
	version        = flag.Bool("version", false, "Print version information and exit")
	test           = flag.Bool("test", false, "Test the config file and exit")
)

func printVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		common.Output(s)
	}
}

func getConfigFilePath() string {
	return *configFilePath
}

func open(filePath string) (*os.File, error) {
	switch filePath {
	case "":
		if env := os.Getenv(core.EnvKey("config", "file", "path")); env != "" {
			if file, err := os.Open(env); err == nil {
				return file, err
			}
		}
		if env := os.Getenv(core.EnvKey("config", "dir", "path")); env != "" {
			if file, err := os.Open(filepath.Join(env, "config.json")); err == nil {
				return file, err
			}
		}
		return os.Open("config.json")
	case "-":
		return os.Stdin, nil
	default:
		return core.OpenFile(filePath)
	}
}

func main() {
	flag.Parse()
	printVersion()
	if *version {
		return
	}
	configFilePath := getConfigFilePath()
	envConfigDirPath := core.EnvKey("config", "dir", "path")
	if _, isSet := os.LookupEnv(envConfigDirPath); !isSet {
		if executablePath, err := os.Executable(); err == nil {
			_ = os.Setenv(envConfigDirPath, filepath.Dir(executablePath))
		}
	}
	file, err := open(configFilePath)
	if err != nil {
		common.ErrOutput(common.Concatenate("config: Failed to open file: ", err))
		os.Exit(1)
	}
	_ = os.Setenv(envConfigDirPath, filepath.Dir(file.Name()))
	instance, err := config.LoadConfig(file)
	_ = file.Close()
	if err != nil {
		common.ErrOutput(common.Concatenate("config: Failed to load config: ", err))
		os.Exit(1)
	}
	if *test {
		common.Output("config: Syntax is OK")
		os.Exit(0)
	}
	runtime.GC()
	instance.Listen(common.ClientErrorMessageHandler, common.ServerErrorMessageHandler, common.ErrOutputErrorHandler)
}
