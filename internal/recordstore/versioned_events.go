package recordstore

import "errors"

// MaxRevisionSubscriptions bounds the process-local notification fanout. A
// notification is only a hint to fetch the complete current snapshot; it is
// not a durable acknowledgement or a replay log.
const MaxRevisionSubscriptions = 64

var ErrRevisionSubscriptionCapacity = errors.New("exact store revision subscription capacity reached")

// RevisionNotification identifies one published immutable generation. Resync
// is true for the initial state and whenever a slow subscriber may have missed
// one or more intermediate revisions.
type RevisionNotification struct {
	RulesetID string
	LineageID string
	Revision  uint64
	Resync    bool
}

type revisionSubscriber struct {
	events chan RevisionNotification
}

// RevisionSubscription owns one bounded process-local stream. Close is
// idempotent and may race with VersionedStore.Close.
type RevisionSubscription struct {
	store      *VersionedStore
	id         uint64
	subscriber *revisionSubscriber
}

func (s *RevisionSubscription) Events() <-chan RevisionNotification {
	if s == nil || s.subscriber == nil {
		return nil
	}
	return s.subscriber.events
}

func (s *RevisionSubscription) Close() {
	if s == nil || s.store == nil || s.subscriber == nil {
		return
	}
	s.store.revisionMu.Lock()
	defer s.store.revisionMu.Unlock()
	if current, ok := s.store.revisionSubscribers[s.id]; ok && current == s.subscriber {
		delete(s.store.revisionSubscribers, s.id)
		close(current.events)
	}
}

// SubscribeRevisions atomically registers a subscriber with its initial
// current generation. Registration and publication share a short mutex that
// is independent of durable writer I/O, so a subscriber cannot miss a
// publication and cancellation does not wait for a stalled commit.
func (s *VersionedStore) SubscribeRevisions() (*RevisionSubscription, error) {
	s.revisionMu.Lock()
	defer s.revisionMu.Unlock()

	current := s.current.Load()
	if current == nil {
		return nil, ErrClosed
	}
	if len(s.revisionSubscribers) >= MaxRevisionSubscriptions {
		return nil, ErrRevisionSubscriptionCapacity
	}
	if s.revisionSubscribers == nil {
		s.revisionSubscribers = make(map[uint64]*revisionSubscriber)
	}
	var id uint64
	for {
		s.nextRevisionSubscriber++
		if s.nextRevisionSubscriber == 0 {
			continue
		}
		if _, exists := s.revisionSubscribers[s.nextRevisionSubscriber]; !exists {
			id = s.nextRevisionSubscriber
			break
		}
	}
	subscriber := &revisionSubscriber{events: make(chan RevisionNotification, 1)}
	metadata := current.snapshot.Metadata()
	subscriber.events <- RevisionNotification{
		RulesetID: metadata.RulesetID,
		LineageID: metadata.LineageID,
		Revision:  metadata.Revision,
		Resync:    true,
	}
	s.revisionSubscribers[id] = subscriber
	return &RevisionSubscription{store: s, id: id, subscriber: subscriber}, nil
}

// publishRevisionLocked runs with revisionMu held after the immutable
// generation has been installed in current. It never blocks a writer on a
// subscriber: a full single-item queue is replaced with the latest revision
// and marked resync.
func (s *VersionedStore) publishRevisionLocked(generation *versionedGeneration) {
	metadata := generation.snapshot.Metadata()
	notification := RevisionNotification{
		RulesetID: metadata.RulesetID,
		LineageID: metadata.LineageID,
		Revision:  metadata.Revision,
	}
	for _, subscriber := range s.revisionSubscribers {
		select {
		case subscriber.events <- notification:
			continue
		default:
		}
		select {
		case <-subscriber.events:
		default:
		}
		coalesced := notification
		coalesced.Resync = true
		select {
		case subscriber.events <- coalesced:
		default:
		}
	}
}
