package routeros

import "strings"

type lexer struct {
	data                 string
	offset, line, column int
}

func (l *lexer) fail(code string) error { return &ParseError{Diagnostic{l.line, l.column, code}} }
func (l *lexer) take() byte {
	c := l.data[l.offset]
	l.offset++
	if c == '\n' {
		l.line++
		l.column = 1
	} else {
		l.column++
	}
	return c
}
func (l *lexer) command() ([]string, int, error) {
	if l.offset == len(l.data) {
		return nil, l.line, nil
	}
	line, start := l.line, l.offset
	tokens := []string{}
	for l.offset < len(l.data) {
		if l.offset-start > MaxLogicalLineBytes {
			return nil, line, l.fail("logical_line_limit")
		}
		c := l.data[l.offset]
		if c == ' ' || c == '\t' {
			l.take()
			continue
		}
		if c == '\n' || c == ';' {
			l.take()
			return tokens, line, nil
		}
		if c == '#' {
			for l.offset < len(l.data) && l.data[l.offset] != '\n' {
				l.take()
			}
			if l.offset-start > MaxLogicalLineBytes {
				return nil, line, l.fail("logical_line_limit")
			}
			continue
		}
		if c == '\\' {
			l.take()
			if l.offset == len(l.data) || l.data[l.offset] != '\n' {
				return nil, line, l.fail("invalid_continuation")
			}
			l.take()
			continue
		}
		var token strings.Builder
		quoted := false
		for l.offset < len(l.data) {
			c = l.data[l.offset]
			if c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '#' {
				break
			}
			if c == '"' {
				if !strings.HasSuffix(token.String(), "=") || strings.Count(token.String(), "=") != 1 {
					return nil, line, l.fail("invalid_quoted_value")
				}
				l.take()
				closed := false
				for l.offset < len(l.data) {
					c = l.take()
					if c == '"' {
						closed = true
						break
					}
					if c == '\n' {
						return nil, line, l.fail("unterminated_string")
					}
					if c == '$' {
						return nil, line, l.fail("interpolation_not_allowed")
					}
					if c == '\\' {
						if l.offset == len(l.data) {
							return nil, line, l.fail("unterminated_escape")
						}
						c = l.take()
						switch c {
						case '"', '\\', '$':
						case 'n':
							c = '\n'
						case 'r':
							c = '\r'
						case 't':
							c = '\t'
						case '_':
							c = ' '
						default:
							first, ok := hexDigit(c)
							if !ok || l.offset == len(l.data) {
								return nil, line, l.fail("unsupported_escape")
							}
							second, ok := hexDigit(l.take())
							if !ok {
								return nil, line, l.fail("unsupported_escape")
							}
							c = first*16 + second
						}
					}
					token.WriteByte(c)
					if token.Len() > MaxValueBytes {
						return nil, line, l.fail("value_limit")
					}
				}
				if !closed {
					return nil, line, l.fail("unterminated_string")
				}
				quoted = true
				break
			}
			if strings.ContainsRune("$[]{}()\\", rune(c)) || c < 32 {
				return nil, line, l.fail("expression_not_allowed")
			}
			token.WriteByte(l.take())
			if token.Len() > MaxValueBytes {
				return nil, line, l.fail("value_limit")
			}
		}
		if quoted && l.offset < len(l.data) && !strings.ContainsRune(" \t\n;#", rune(l.data[l.offset])) {
			return nil, line, l.fail("value_concatenation_not_allowed")
		}
		if token.Len() == 0 {
			return nil, line, l.fail("empty_token")
		}
		tokens = append(tokens, token.String())
		if l.offset-start > MaxLogicalLineBytes {
			return nil, line, l.fail("logical_line_limit")
		}
	}
	return tokens, line, nil
}
func hexDigit(c byte) (byte, bool) {
	if c >= '0' && c <= '9' {
		return c - '0', true
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10, true
	}
	return 0, false
}
