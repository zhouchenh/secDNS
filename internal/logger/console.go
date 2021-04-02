package logger

import (
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"os"
	"strings"
	"time"
)

var (
	stdoutConsoleWriter = newConsoleWriter(os.Stdout)
	stderrConsoleWriter = newConsoleWriter(os.Stderr)
)

const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan
	colorWhite
	colorBold     = 1
	colorDarkGray = 90
)

func newConsoleWriter(output io.Writer) *zerolog.ConsoleWriter {
	cw := &zerolog.ConsoleWriter{
		Out:        output,
		TimeFormat: time.UnixDate,
		NoColor:    os.Getenv("TERM") == "",
	}
	cw.FormatLevel = levelFormatter(cw)
	return cw
}

func colorize(s interface{}, c int, disabled bool) string {
	if disabled {
		return fmt.Sprintf("%s", s)
	}
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m", c, s)
}

func levelFormatter(consoleWriter *zerolog.ConsoleWriter) zerolog.Formatter {
	return func(i interface{}) string {
		var l string
		if ll, ok := i.(string); ok {
			switch ll {
			case "trace":
				l = colorize("Trace", colorCyan, consoleWriter.NoColor)
			case "debug":
				l = colorize("Debug", colorBlue, consoleWriter.NoColor)
			case "info":
				l = colorize("Info", colorGreen, consoleWriter.NoColor)
			case "warn":
				l = colorize("Warning", colorYellow, consoleWriter.NoColor)
			case "error":
				l = colorize(colorize("Error", colorRed, consoleWriter.NoColor), colorBold, consoleWriter.NoColor)
			case "fatal":
				l = colorize(colorize("Fatal", colorMagenta, consoleWriter.NoColor), colorBold, consoleWriter.NoColor)
			case "panic":
				l = colorize(colorize("Panic", colorMagenta, consoleWriter.NoColor), colorBold, consoleWriter.NoColor)
			default:
				l = colorize("???", colorBold, consoleWriter.NoColor)
			}
		} else {
			if i == nil {
				l = colorize("???", colorBold, consoleWriter.NoColor)
			} else {
				l = strings.ToUpper(fmt.Sprintf("%s", i))[0:3]
			}
		}
		return "[" + l + "]"
	}
}

func Color() bool {
	return !stdoutConsoleWriter.NoColor && !stderrConsoleWriter.NoColor
}

func SetColor(color bool) {
	stdoutConsoleWriter.NoColor = !color
	stderrConsoleWriter.NoColor = !color
}

func Output() io.Writer {
	return stdoutConsoleWriter.Out
}

func SetOutput(output io.Writer) {
	stdoutConsoleWriter.Out = output
}

func ErrorOutput() io.Writer {
	return stderrConsoleWriter.Out
}

func SetErrorOutput(output io.Writer) {
	stderrConsoleWriter.Out = output
}
