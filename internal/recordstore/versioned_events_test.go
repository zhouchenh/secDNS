package recordstore

import (
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

func receiveRevision(t *testing.T, subscription *RevisionSubscription) RevisionNotification {
	t.Helper()
	select {
	case notification, ok := <-subscription.Events():
		if !ok {
			t.Fatal("revision subscription closed")
		}
		return notification
	case <-time.After(time.Second):
		t.Fatal("revision notification timed out")
		return RevisionNotification{}
	}
}

func assertNoRevision(t *testing.T, subscription *RevisionSubscription) {
	t.Helper()
	select {
	case notification, ok := <-subscription.Events():
		t.Fatalf("unexpected revision notification: %+v open=%v", notification, ok)
	default:
	}
}

func TestVersionedRevisionSubscriptionPublishesAfterGeneration(t *testing.T) {
	bothVersioned(t, func(t *testing.T, store *VersionedStore) {
		subscription, err := store.SubscribeRevisions()
		if err != nil {
			t.Fatal(err)
		}
		defer subscription.Close()
		initial := receiveRevision(t, subscription)
		if initial != (RevisionNotification{RulesetID: "test", LineageID: "lineage", Revision: 1, Resync: true}) {
			t.Fatal("initial notification", initial)
		}

		base, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		type hookObservation struct {
			revision uint64
			notified bool
		}
		observed := make(chan hookObservation, 1)
		release := make(chan struct{})
		store.hooks.afterCommit = func() {
			view, acquireErr := store.Acquire()
			if acquireErr != nil {
				observed <- hookObservation{}
				return
			}
			notified := false
			select {
			case <-subscription.Events():
				notified = true
			default:
			}
			observed <- hookObservation{revision: view.Metadata().Revision, notified: notified}
			<-release
		}
		result := make(chan error, 1)
		go func() {
			_, replaceErr := store.Replace(expectation(base), "event-order", exactRecords("192.0.2.1"))
			result <- replaceErr
		}()
		observedValue := <-observed
		if observedValue.revision != 1 || observedValue.notified {
			close(release)
			t.Fatal("commit hook observed publication", observedValue)
		}
		close(release)
		if err = <-result; err != nil {
			t.Fatal(err)
		}
		notification := receiveRevision(t, subscription)
		if notification != (RevisionNotification{RulesetID: "test", LineageID: "lineage", Revision: 2}) {
			t.Fatal("published notification", notification)
		}
		current, err := store.Acquire()
		if err != nil || current.Metadata().Revision != notification.Revision {
			t.Fatal("notification preceded publication", current.Metadata(), err)
		}
	})
}

func TestVersionedRevisionSubscriptionOnlyReportsNewPublications(t *testing.T) {
	bothVersioned(t, func(t *testing.T, store *VersionedStore) {
		subscription, err := store.SubscribeRevisions()
		if err != nil {
			t.Fatal(err)
		}
		defer subscription.Close()
		_ = receiveRevision(t, subscription)
		base, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}

		store.hooks.beforeCommit = func(*sql.Tx) error { return errors.New("synthetic commit failure") }
		if _, err = store.Replace(expectation(base), "event-failed", exactRecords("192.0.2.1")); !errors.Is(err, ErrVersionedStorage) {
			t.Fatal(err)
		}
		assertNoRevision(t, subscription)

		store.hooks = versionedHooks{}
		receipt, err := store.Replace(expectation(base), "event-same-content", nil)
		if err != nil || receipt.Revision != 2 {
			t.Fatal(receipt, err)
		}
		if notification := receiveRevision(t, subscription); notification.Revision != 2 || notification.Resync {
			t.Fatal(notification)
		}
		if replay, replayErr := store.Replace(expectation(base), "event-same-content", nil); replayErr != nil || replay != receipt {
			t.Fatal(replay, replayErr)
		}
		assertNoRevision(t, subscription)
	})
}

func TestVersionedRevisionSubscriptionCoalescesSlowConsumer(t *testing.T) {
	bothVersioned(t, func(t *testing.T, store *VersionedStore) {
		subscription, err := store.SubscribeRevisions()
		if err != nil {
			t.Fatal(err)
		}
		defer subscription.Close()
		_ = receiveRevision(t, subscription)

		base, _ := store.Acquire()
		if _, err = store.Replace(expectation(base), "event-two", exactRecords("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
		base, _ = store.Acquire()
		if _, err = store.Replace(expectation(base), "event-three", exactRecords("192.0.2.2")); err != nil {
			t.Fatal(err)
		}
		notification := receiveRevision(t, subscription)
		if notification.Revision != 3 || !notification.Resync {
			t.Fatal("slow consumer did not receive latest resync", notification)
		}
		assertNoRevision(t, subscription)
	})
}

func TestVersionedRevisionSubscriptionCapacityCancelAndStoreClose(t *testing.T) {
	store, err := NewVersionedMemory(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	subscriptions := make([]*RevisionSubscription, 0, MaxRevisionSubscriptions)
	for range MaxRevisionSubscriptions {
		subscription, subscribeErr := store.SubscribeRevisions()
		if subscribeErr != nil {
			t.Fatal(subscribeErr)
		}
		_ = receiveRevision(t, subscription)
		subscriptions = append(subscriptions, subscription)
	}
	if _, err = store.SubscribeRevisions(); !errors.Is(err, ErrRevisionSubscriptionCapacity) {
		t.Fatal("subscription capacity", err)
	}
	subscriptions[0].Close()
	subscriptions[0].Close()
	if _, ok := <-subscriptions[0].Events(); ok {
		t.Fatal("cancelled subscription remained open")
	}
	replacement, err := store.SubscribeRevisions()
	if err != nil {
		t.Fatal("cancel did not free capacity", err)
	}
	_ = receiveRevision(t, replacement)

	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, subscription := range append(subscriptions[1:], replacement) {
		if _, ok := <-subscription.Events(); ok {
			t.Fatal("store close left subscription open")
		}
		subscription.Close()
	}
	if _, err = store.SubscribeRevisions(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed store admitted subscription", err)
	}
}

func TestVersionedRevisionSubscriptionRegistrationCannotMissConcurrentCommit(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		store, err := NewVersionedMemory(enrollment)
		if err != nil {
			t.Fatal(err)
		}
		base, _ := store.Acquire()
		start := make(chan struct{})
		writeDone := make(chan error, 1)
		subscribeDone := make(chan struct {
			subscription *RevisionSubscription
			err          error
		}, 1)
		go func() {
			<-start
			_, replaceErr := store.Replace(expectation(base), "registration-race", nil)
			writeDone <- replaceErr
		}()
		go func() {
			<-start
			subscription, subscribeErr := store.SubscribeRevisions()
			subscribeDone <- struct {
				subscription *RevisionSubscription
				err          error
			}{subscription, subscribeErr}
		}()
		close(start)
		subscribed := <-subscribeDone
		if subscribed.err != nil {
			t.Fatal(subscribed.err)
		}
		first := receiveRevision(t, subscribed.subscription)
		if err = <-writeDone; err != nil {
			t.Fatal(err)
		}
		switch first.Revision {
		case 1:
			if next := receiveRevision(t, subscribed.subscription); next.Revision != 2 {
				t.Fatal("subscription missed concurrent publication", first, next)
			}
		case 2:
			if !first.Resync {
				t.Fatal("current generation was not an initial/resync hint", first)
			}
		default:
			t.Fatal("unexpected initial revision", first)
		}
		subscribed.subscription.Close()
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVersionedRevisionSubscriptionDoesNotWaitForBlockedCommit(t *testing.T) {
	bothVersioned(t, func(t *testing.T, store *VersionedStore) {
		base, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		commitEntered := make(chan struct{})
		releaseCommit := make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(releaseCommit) })
		store.hooks.beforeCommit = func(*sql.Tx) error {
			close(commitEntered)
			<-releaseCommit
			return nil
		}
		replaceDone := make(chan error, 1)
		go func() {
			_, replaceErr := store.Replace(expectation(base), "blocked-commit", exactRecords("192.0.2.1"))
			replaceDone <- replaceErr
		}()
		select {
		case <-commitEntered:
		case <-time.After(time.Second):
			t.Fatal("replacement did not reach blocked commit")
		}

		type subscribeResult struct {
			subscription *RevisionSubscription
			err          error
		}
		subscribe := func() *RevisionSubscription {
			t.Helper()
			done := make(chan subscribeResult, 1)
			go func() {
				subscription, subscribeErr := store.SubscribeRevisions()
				done <- subscribeResult{subscription: subscription, err: subscribeErr}
			}()
			select {
			case result := <-done:
				if result.err != nil {
					t.Fatal(result.err)
				}
				return result.subscription
			case <-time.After(250 * time.Millisecond):
				t.Fatal("subscription waited for blocked durable commit")
				return nil
			}
		}

		survivor := subscribe()
		defer survivor.Close()
		if initial := receiveRevision(t, survivor); initial.Revision != 1 || !initial.Resync {
			t.Fatal("subscription did not start from published generation", initial)
		}
		cancelled := subscribe()
		_ = receiveRevision(t, cancelled)
		cancelDone := make(chan struct{})
		go func() {
			cancelled.Close()
			close(cancelDone)
		}()
		select {
		case <-cancelDone:
		case <-time.After(250 * time.Millisecond):
			t.Fatal("subscription cancellation waited for blocked durable commit")
		}

		releaseOnce.Do(func() { close(releaseCommit) })
		if err = <-replaceDone; err != nil {
			t.Fatal(err)
		}
		if notification := receiveRevision(t, survivor); notification.Revision != 2 || notification.Resync {
			t.Fatal("subscription missed publication after blocked commit", notification)
		}
	})
}

func TestVersionedRevisionSubscriptionCancelMayRaceStoreClose(t *testing.T) {
	for range 100 {
		store, err := NewVersionedMemory(enrollment)
		if err != nil {
			t.Fatal(err)
		}
		subscription, err := store.SubscribeRevisions()
		if err != nil {
			t.Fatal(err)
		}
		_ = receiveRevision(t, subscription)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			subscription.Close()
		}()
		go func() {
			defer wait.Done()
			if closeErr := store.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}()
		wait.Wait()
		if _, open := <-subscription.Events(); open {
			t.Fatal("racing close left subscription open")
		}
	}
}
