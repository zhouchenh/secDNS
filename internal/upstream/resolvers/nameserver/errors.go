package nameserver

import "errors"

// ErrNoMatchingResponse is returned when the upstream sends only unsolicited or
// mismatched datagrams (wrong transaction ID or question) and no response matching
// the outstanding query arrives within the bounded number of read attempts.
var ErrNoMatchingResponse = errors.New("nameserver: no matching response from upstream")
