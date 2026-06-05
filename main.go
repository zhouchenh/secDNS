package main

import (
	"flag"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/config"
	"github.com/zhouchenh/secDNS/internal/core"
	_ "github.com/zhouchenh/secDNS/internal/features"
	"github.com/zhouchenh/secDNS/internal/logger"
	"os"
	"path/filepath"
	"runtime"
)

var (
	configFilePath = flag.String("config", "", "Specify a config file")
	version        = flag.Bool("version", false, "Print version information and exit")
	test           = flag.Bool("test", false, "Test the config file and exit")
	logLevel       = flag.String("log-level", "", "Log verbosity: trace|debug|info|warn|error|off (env "+core.EnvKey("log", "level")+")")
)

// applyLogLevel sets the log level from the --log-level flag, falling back to the
// SECDNS_LOG_LEVEL env var, then the default. An unrecognized value keeps the default
// and warns rather than aborting.
func applyLogLevel(flagValue string) {
	value := flagValue
	if value == "" {
		value = os.Getenv(core.EnvKey("log", "level"))
	}
	if value == "" {
		return
	}
	if level, ok := logger.ParseLevel(value); ok {
		logger.SetLogLevel(level)
	} else {
		logger.Warning().Msgf("config: unknown log level %q; keeping default", value)
	}
}

func printVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		common.Output(s)
	}
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

// Process exit codes. A failed startup must be non-zero so a supervisor (systemd,
// Docker, Kubernetes) detects it instead of treating a server that never started as a
// clean exit.
const (
	exitOK       = 0 // ran to completion, or --version/--test succeeded
	exitStartup  = 1 // a config file was named or found but could not be opened or loaded
	exitNoConfig = 2 // no config file was specified and none could be found (usage error)
)

func main() {
	flag.Parse()
	os.Exit(run(*configFilePath, *version, *test, *logLevel))
}

// run executes the program and returns the process exit code. It is separated from
// main so the startup and exit paths are testable without spawning a process: every
// failure path returns a non-zero code rather than calling os.Exit, and previously a
// missing config exited 0 (a silent success) — it now exits exitNoConfig.
func run(configFilePath string, showVersion, testOnly bool, logLevelValue string) int {
	applyLogLevel(logLevelValue)
	printVersion()
	if showVersion {
		return exitOK
	}
	envConfigDirPath := core.EnvKey("config", "dir", "path")
	if _, isSet := os.LookupEnv(envConfigDirPath); !isSet {
		if executablePath, err := os.Executable(); err == nil {
			_ = os.Setenv(envConfigDirPath, filepath.Dir(executablePath))
		}
	}
	file, err := open(configFilePath)
	if err != nil {
		if configFilePath == "" {
			common.ErrOutput(common.Concatenate(
				"config: no config file found; specify one with -config <path>, set ",
				core.EnvKey("config", "file", "path"),
				", or place config.json next to the executable"))
			flag.PrintDefaults()
			return exitNoConfig
		}
		common.ErrOutput(common.Concatenate("config: Failed to open file: ", err))
		return exitStartup
	}
	_ = os.Setenv(envConfigDirPath, filepath.Dir(file.Name()))
	configSource := file.Name()
	instance, err := config.LoadConfig(file)
	_ = file.Close()
	if err != nil {
		common.ErrOutput(common.Concatenate("config: Failed to load config: ", err))
		return exitStartup
	}
	logger.Info().Str("source", configSource).Msg("config loaded")
	if testOnly {
		common.Output("config: Syntax is OK")
		return exitOK
	}
	runtime.GC()
	instance.Listen(common.ClientErrorMessageHandler, common.ServerErrorMessageHandler, common.ErrOutputErrorHandler)
	return exitOK
}
