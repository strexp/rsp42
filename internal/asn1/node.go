package asn1

import "fmt"

// Node is a mutable BER-TLV tree used when a structure must be edited and
// re-encoded (e.g. SAIP ProfileElements). Unlike TLV it owns its bytes and can
// be modified; minimal definite-length encoding is used on output, which all
// SGP.22/SAIP senders also use.
type Node struct {
	Tag         []byte
	Value       []byte // primitive content
	Children    []*Node
	Constructed bool
}

// ParseNode parses a single TLV into a Node and returns the remaining bytes.
func ParseNode(b []byte) (*Node, []byte, error) {
	t, rest, err := ReadTLV(b)
	if err != nil {
		return nil, nil, err
	}
	n := &Node{Tag: t.Tag, Constructed: t.Constructed}
	if t.Constructed {
		kids, err := ReadTLVs(t.Value)
		if err != nil {
			return nil, nil, err
		}
		for i := range kids {
			child, _, err := ParseNode(kids[i].Raw)
			if err != nil {
				return nil, nil, err
			}
			n.Children = append(n.Children, child)
		}
	} else {
		n.Value = t.Value
	}
	return n, rest, nil
}

// ParseNodes parses a concatenation of TLVs (e.g. a UPP).
func ParseNodes(b []byte) ([]*Node, error) {
	var out []*Node
	for len(b) > 0 {
		n, rest, err := ParseNode(b)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
		b = rest
	}
	return out, nil
}

// Encode serializes the node (minimal definite lengths).
func (n *Node) Encode() []byte {
	var content []byte
	if n.Constructed {
		for _, c := range n.Children {
			content = append(content, c.Encode()...)
		}
	} else {
		content = n.Value
	}
	out := make([]byte, 0, len(n.Tag)+4+len(content))
	out = append(out, n.Tag...)
	out = append(out, EncodeLength(len(content))...)
	out = append(out, content...)
	return out
}

// Find returns the first child with the given tag.
func (n *Node) Find(tag []byte) *Node {
	for _, c := range n.Children {
		if bytesEqual(c.Tag, tag) {
			return c
		}
	}
	return nil
}

// FindAll returns every child with the given tag.
func (n *Node) FindAll(tag []byte) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if bytesEqual(c.Tag, tag) {
			out = append(out, c)
		}
	}
	return out
}

// RemoveAll removes every child with the given tag.
func (n *Node) RemoveAll(tag []byte) {
	kept := n.Children[:0]
	for _, c := range n.Children {
		if !bytesEqual(c.Tag, tag) {
			kept = append(kept, c)
		}
	}
	n.Children = kept
}

// AppendChild appends a child (marking the node constructed).
func (n *Node) AppendChild(c *Node) {
	n.Constructed = true
	n.Children = append(n.Children, c)
}

// NewPrimitive builds a primitive node.
func NewPrimitive(tag, value []byte) *Node {
	return &Node{Tag: append([]byte(nil), tag...), Value: append([]byte(nil), value...)}
}

// NewConstructed builds a constructed node.
func NewConstructed(tag []byte, children ...*Node) *Node {
	return &Node{Tag: append([]byte(nil), tag...), Constructed: true, Children: children}
}

// MustParseNode panics on parse errors; for tests and constant data.
func MustParseNode(b []byte) *Node {
	n, _, err := ParseNode(b)
	if err != nil {
		panic(fmt.Sprintf("asn1: %v", err))
	}
	return n
}
