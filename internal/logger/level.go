package logger

import "github.com/rs/zerolog"

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
