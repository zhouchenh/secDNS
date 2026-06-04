package logger

import "testing"

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
		ok   bool
	}{
		{"trace", TraceLevel, true},
		{"debug", DebugLevel, true},
		{"INFO", InfoLevel, true},
		{" warn ", WarningLevel, true},
		{"warning", WarningLevel, true},
		{"error", ErrorLevel, true},
		{"quiet", ErrorLevel, true},
		{"off", Disabled, true},
		{"bogus", DefaultLogLevel, false},
		{"", DefaultLogLevel, false},
	}
	for _, c := range cases {
		got, ok := ParseLevel(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseLevel(%q) = (%v,%v), want (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSetLogLevelRoundTrip(t *testing.T) {
	orig := LogLevel()
	defer SetLogLevel(orig)

	SetLogLevel(DebugLevel)
	if LogLevel() != DebugLevel {
		t.Fatalf("after SetLogLevel(Debug), LogLevel()=%v", LogLevel())
	}
	SetLogLevel(ErrorLevel)
	if LogLevel() != ErrorLevel {
		t.Fatalf("after SetLogLevel(Error), LogLevel()=%v", LogLevel())
	}
}
