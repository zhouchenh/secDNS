package snapshotfollower

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

const (
	maxSSELineBytes   = 1 << 10
	maxSSEEventBytes  = 4 << 10
	maxSSEStreamBytes = 64 << 10
)

type eventData struct {
	Status    string `json:"status"`
	RulesetID string `json:"ruleset_id"`
	LineageID string `json:"lineage_id"`
	Revision  string `json:"revision"`
}

type countingReader struct {
	reader io.Reader
	total  int
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	remaining := maxSSEStreamBytes + 1 - r.total
	if remaining <= 0 {
		return 0, errors.New("stream limit")
	}
	if len(buffer) > remaining {
		buffer = buffer[:remaining]
	}
	n, err := r.reader.Read(buffer)
	r.total += n
	return n, err
}

func boundedLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if len(line) > maxSSELineBytes {
		return "", errors.New("line limit")
	}
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func (w *Worker) consumeEvents(ctx context.Context, body io.Reader) (bool, string) {
	counter := &countingReader{reader: body}
	reader := bufio.NewReaderSize(counter, maxSSELineBytes+1)
	fields := map[string]string{}
	eventBytes := 0
	for {
		if ctx.Err() != nil {
			return false, errorCanceled
		}
		line, err := boundedLine(reader)
		if counter.total > maxSSEStreamBytes {
			return false, errorProtocol
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, errorTransport
			}
			return false, errorProtocol
		}
		eventBytes += len(line) + 1
		if eventBytes > maxSSEEventBytes {
			return false, errorProtocol
		}
		if line == "" {
			if len(fields) == 0 {
				eventBytes = 0
				continue
			}
			if len(fields) != 3 || fields["event"] != "snapshot-revision" || fields["id"] == "" || fields["data"] == "" {
				return false, errorProtocol
			}
			var data eventData
			decoder := json.NewDecoder(strings.NewReader(fields["data"]))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&data) != nil || decoder.Decode(new(any)) != io.EOF {
				return false, errorProtocol
			}
			revision, err := strconv.ParseUint(data.Revision, 10, 64)
			if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != data.Revision || data.RulesetID != w.config.Enrollment.RulesetID || data.LineageID != w.config.Enrollment.LineageID || fields["id"] != data.LineageID+":"+data.Revision {
				return false, errorProtocol
			}
			if data.Status != "advanced" && data.Status != "resync" {
				return false, errorProtocol
			}
			return true, ""
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found || name != "id" && name != "event" && name != "data" || fields[name] != "" {
			return false, errorProtocol
		}
		fields[name] = strings.TrimPrefix(value, " ")
	}
}

func (w *Worker) stream(parent context.Context) (bool, string) {
	cursor, ready := w.currentCursor()
	if !ready {
		return false, errorStorage
	}
	ctx, cancel := context.WithTimeout(parent, w.eventTimeout)
	defer cancel()
	request, err := w.request(ctx, w.endpoint("/snapshot/events"))
	if err != nil {
		return false, errorProtocol
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", cursor)
	response, err := w.client.Do(request)
	if err != nil {
		if parent.Err() != nil {
			return false, errorCanceled
		}
		return false, errorTransport
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return false, errorAuth
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || err != nil || !strings.EqualFold(mediaType, "text/event-stream") {
		return false, errorProtocol
	}
	w.update(func(status *Status) {
		status.ConnectionState = "streaming"
		status.ErrorCategory = ""
	})
	trigger, category := w.consumeEvents(ctx, response.Body)
	if category == errorCanceled && parent.Err() == nil {
		category = errorTransport
	}
	return trigger, category
}
