package cache

import "testing"

func TestLRUList_AddToFront(t *testing.T) {
	lru := NewLRUList()

	node1 := lru.AddToFront("key1")
	if lru.Size() != 1 {
		t.Errorf("Expected size 1, got %d", lru.Size())
	}
	if lru.head != node1 || lru.tail != node1 {
		t.Error("Single node should be both head and tail")
	}

	node2 := lru.AddToFront("key2")
	if lru.Size() != 2 {
		t.Errorf("Expected size 2, got %d", lru.Size())
	}
	if lru.head != node2 {
		t.Error("New node should be head")
	}
	if lru.tail != node1 {
		t.Error("Old node should be tail")
	}
	if node2.next != node1 || node1.prev != node2 {
		t.Error("Nodes not properly linked")
	}
}

func TestLRUList_Remove(t *testing.T) {
	lru := NewLRUList()

	node1 := lru.AddToFront("key1")
	node2 := lru.AddToFront("key2")
	node3 := lru.AddToFront("key3")

	// Remove middle node
	lru.Remove(node2)
	if lru.Size() != 2 {
		t.Errorf("Expected size 2, got %d", lru.Size())
	}
	if node3.next != node1 {
		t.Error("node3 should point to node1")
	}
	if node1.prev != node3 {
		t.Error("node1 should point back to node3")
	}

	// Remove head
	lru.Remove(node3)
	if lru.head != node1 {
		t.Error("node1 should be head")
	}
	if lru.tail != node1 {
		t.Error("node1 should be tail")
	}
	if lru.Size() != 1 {
		t.Errorf("Expected size 1, got %d", lru.Size())
	}

	// Remove last node
	lru.Remove(node1)
	if lru.head != nil || lru.tail != nil {
		t.Error("List should be empty")
	}
	if lru.Size() != 0 {
		t.Errorf("Expected size 0, got %d", lru.Size())
	}
}

func TestLRUList_MoveToFront(t *testing.T) {
	lru := NewLRUList()

	node1 := lru.AddToFront("key1")
	node2 := lru.AddToFront("key2")
	node3 := lru.AddToFront("key3")

	// Move tail to front
	lru.MoveToFront(node1)
	if lru.head != node1 {
		t.Error("node1 should be head")
	}
	if lru.tail != node2 {
		t.Error("node2 should be tail")
	}
	if node1.next != node3 {
		t.Error("node1 should point to node3")
	}

	// Moving head to front should be no-op
	lru.MoveToFront(node1)
	if lru.head != node1 {
		t.Error("node1 should still be head")
	}

	// Move middle to front
	lru.MoveToFront(node3)
	if lru.head != node3 {
		t.Error("node3 should be head")
	}
	if node3.next != node1 {
		t.Error("node3 should point to node1")
	}
}

func TestLRUList_RemoveTail(t *testing.T) {
	lru := NewLRUList()

	// Empty list
	if node := lru.RemoveTail(); node != nil {
		t.Error("RemoveTail on empty list should return nil")
	}

	node1 := lru.AddToFront("key1")
	node2 := lru.AddToFront("key2")
	_ = lru.AddToFront("key3")

	// Remove tail
	removed := lru.RemoveTail()
	if removed != node1 {
		t.Error("Should remove node1 (tail)")
	}
	if lru.tail != node2 {
		t.Error("node2 should be new tail")
	}
	if lru.Size() != 2 {
		t.Errorf("Expected size 2, got %d", lru.Size())
	}
}

func TestLRUList_Clear(t *testing.T) {
	lru := NewLRUList()

	lru.AddToFront("key1")
	lru.AddToFront("key2")
	lru.AddToFront("key3")

	lru.Clear()

	if lru.Size() != 0 {
		t.Errorf("Expected size 0, got %d", lru.Size())
	}
	if lru.head != nil || lru.tail != nil {
		t.Error("Head and tail should be nil after clear")
	}
}

func TestLRUList_LRUBehavior(t *testing.T) {
	lru := NewLRUList()

	// Simulate LRU cache behavior
	keys := []string{"a", "b", "c", "d", "e"}
	nodes := make(map[string]*LRUNode)

	// Add keys
	for _, key := range keys {
		nodes[key] = lru.AddToFront(key)
	}

	// Access "a" and "c" (move to front)
	lru.MoveToFront(nodes["a"])
	lru.MoveToFront(nodes["c"])

	// LRU order should be: c, a, e, d, b
	// Remove tail (should be "b")
	removed := lru.RemoveTail()
	if removed.key != "b" {
		t.Errorf("Expected to evict 'b', got '%s'", removed.key)
	}

	// Remove tail again (should be "d")
	removed = lru.RemoveTail()
	if removed.key != "d" {
		t.Errorf("Expected to evict 'd', got '%s'", removed.key)
	}
}
