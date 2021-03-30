package alias

import "errors"

var ErrAliasSameAsName = errors.New("upstream/resolvers/alias: Alias same as name")
