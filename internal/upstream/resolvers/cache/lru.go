package cache

// LRUList implements a doubly-linked list for LRU (Least Recently Used) cache eviction.
// It provides O(1) operations for add, remove, and move operations.
type LRUList struct {
	head *LRUNode
	tail *LRUNode
	size int
}

// LRUNode represents a node in the doubly-linked list.
type LRUNode struct {
	key  string
	prev *LRUNode
	next *LRUNode
}

// NewLRUList creates a new empty LRU list.
func NewLRUList() *LRUList {
	return &LRUList{
		head: nil,
		tail: nil,
		size: 0,
	}
}

// AddToFront adds a new key to the front of the list (most recently used).
// Returns the created node.
// Time complexity: O(1)
func (l *LRUList) AddToFront(key string) *LRUNode {
	node := &LRUNode{
		key:  key,
		prev: nil,
		next: l.head,
	}

	if l.head != nil {
		l.head.prev = node
	}
	l.head = node

	if l.tail == nil {
		l.tail = node
	}

	l.size++
	return node
}

// Remove removes a node from the list.
// Time complexity: O(1)
func (l *LRUList) Remove(node *LRUNode) {
	if node == nil {
		return
	}

	// Update previous node
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		// This is the head
		l.head = node.next
	}

	// Update next node
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		// This is the tail
		l.tail = node.prev
	}

	// Clear node pointers (help GC)
	node.prev = nil
	node.next = nil

	l.size--
}

// MoveToFront moves an existing node to the front of the list.
// Time complexity: O(1)
func (l *LRUList) MoveToFront(node *LRUNode) {
	if node == nil || node == l.head {
		return // Already at front or nil
	}

	// Remove from current position
	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		// This is the tail
		l.tail = node.prev
	}

	// Add to front
	node.prev = nil
	node.next = l.head
	if l.head != nil {
		l.head.prev = node
	}
	l.head = node
}

// RemoveTail removes and returns the tail node (least recently used).
// Returns nil if the list is empty.
// Time complexity: O(1)
func (l *LRUList) RemoveTail() *LRUNode {
	if l.tail == nil {
		return nil
	}

	node := l.tail
	l.Remove(node)
	return node
}

// Size returns the current number of nodes in the list.
func (l *LRUList) Size() int {
	return l.size
}

// Clear removes all nodes from the list.
func (l *LRUList) Clear() {
	l.head = nil
	l.tail = nil
	l.size = 0
}
