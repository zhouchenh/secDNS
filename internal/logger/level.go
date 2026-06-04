package logger

import (
	"strings"

	"github.com/rs/zerolog"
)

type Level zerolog.Level

const (
	// DebugLevel defines debug log level.
	DebugLevel = Level(zerolog.DebugLevel)
	// InfoLevel defines info log level.
	InfoLevel = Level(zerolog.InfoLevel)
	// WarningLevel defines warn log level.
	WarningLevel = Level(zerolog.WarnLevel)
	// ErrorLevel defines error log level.
	ErrorLevel = Level(zerolog.ErrorLevel)
	// FatalLevel defines fatal log level.
	FatalLevel = Level(zerolog.FatalLevel)
	// PanicLevel defines panic log level.
	PanicLevel = Level(zerolog.PanicLevel)
	// NoLevel defines an absent log level.
	NoLevel = Level(zerolog.NoLevel)
	// Disabled disables the logger.
	Disabled = Level(zerolog.Disabled)
	// TraceLevel defines trace log level.
	TraceLevel = Level(zerolog.TraceLevel)
)

const DefaultLogLevel = WarningLevel

func LogLevel() Level {
	if stdoutLevel, stderrLevel := stdoutLogger.GetLevel(), stderrLogger.GetLevel(); stdoutLevel < stderrLevel {
		return Level(stdoutLevel)
	} else {
		return Level(stderrLevel)
	}
}

func SetLogLevel(level Level) {
	stdoutLogger = stdoutLogger.Level(zerolog.Level(level))
	stderrLogger = stderrLogger.Level(zerolog.Level(level))
}

// ParseLevel maps a case-insensitive level name to a Level. It reports false for an
// unrecognized name (callers should keep the current/default level and warn).
func ParseLevel(name string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "trace":
		return TraceLevel, true
	case "debug":
		return DebugLevel, true
	case "info":
		return InfoLevel, true
	case "warn", "warning":
		return WarningLevel, true
	case "error", "quiet":
		return ErrorLevel, true
	case "fatal":
		return FatalLevel, true
	case "off", "none", "disabled":
		return Disabled, true
	default:
		return DefaultLogLevel, false
	}
}
