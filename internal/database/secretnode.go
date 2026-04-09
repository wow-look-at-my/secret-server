package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	sqlcdb "github.com/wow-look-at-my/secret-server/internal/database/sqlc"
)

// NodeKind is the DB-layer value of the secret_nodes.kind column. It is used
// in sqlc params and in a handful of internal switches (migration, hydrate).
// It is deliberately NOT exposed on the ISecretNode interface — callers that
// need to know whether a node is a leaf already hold the concrete type.
type NodeKind string

const (
	KindSecret NodeKind = "secret"
	KindGroup  NodeKind = "group"
)

// ISecretNode is the composite-pattern interface over the secret tree.
// Children() returns the children of a group (possibly empty) and always
// returns nil for a leaf Secret. That makes tree walks uniform — no
// type-switch at the call site.
type ISecretNode interface {
	ID() string
	Name() string
	ParentID() *string
	Children() []ISecretNode
}

// Secret is a leaf node holding a single encrypted key/value pair.
// Value is plaintext once populated by a read that ran DecryptValue.
type Secret struct {
	id        string
	name      string
	parentID  *string
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *Secret) ID() string              { return s.id }
func (s *Secret) Name() string            { return s.name }
func (s *Secret) ParentID() *string       { return s.parentID }
func (s *Secret) Children() []ISecretNode { return nil }

// SecretGroup is a composite node that holds zero or more child nodes.
type SecretGroup struct {
	id        string
	name      string
	parentID  *string
	children  []ISecretNode
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (g *SecretGroup) ID() string              { return g.id }
func (g *SecretGroup) Name() string            { return g.name }
func (g *SecretGroup) ParentID() *string       { return g.parentID }
func (g *SecretGroup) Children() []ISecretNode { return g.children }

// Q returns the underlying sqlc Queries struct so handlers can make direct
// calls without going through a wrapper for every simple operation.
func (d *DB) Q() *sqlcdb.Queries { return d.q }

// EncryptValue and DecryptValue expose the package-private encryptor so
// handlers can encrypt on write and decrypt on read without importing crypto.
// Values are stored base64-encoded after AES-256-GCM encryption.
func (d *DB) EncryptValue(plaintext string) ([]byte, error) {
	encrypted, err := d.encryptor.Encrypt([]byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("encrypt value: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(encrypted)), nil
}

func (d *DB) DecryptValue(enc []byte) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return "", fmt.Errorf("decode secret value: %w", err)
	}
	plaintext, err := d.encryptor.Decrypt(encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}

// CreateGroup inserts a group node with the given parent (nil = root).
func (d *DB) CreateGroup(parentID *string, name string) (*SecretGroup, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	err := d.q.CreateSecretNode(context.Background(), sqlcdb.CreateSecretNodeParams{
		ID:        id,
		Kind:      string(KindGroup),
		ParentID:  nullStringFromPtr(parentID),
		Name:      name,
		Value:     nil,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert group: %w", err)
	}
	return &SecretGroup{id: id, name: name, parentID: parentID, CreatedAt: now, UpdatedAt: now}, nil
}

// CreateSecret inserts a leaf secret with an encrypted value. parentID may
// be nil to create a root-level loose secret (used by the migration).
func (d *DB) CreateSecret(parentID *string, name, plaintext string) (*Secret, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	enc, err := d.EncryptValue(plaintext)
	if err != nil {
		return nil, err
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	err = d.q.CreateSecretNode(context.Background(), sqlcdb.CreateSecretNodeParams{
		ID:        id,
		Kind:      string(KindSecret),
		ParentID:  nullStringFromPtr(parentID),
		Name:      name,
		Value:     enc,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert secret: %w", err)
	}
	return &Secret{id: id, name: name, parentID: parentID, CreatedAt: now, UpdatedAt: now}, nil
}

// GetSecret fetches a single secret leaf by ID and decrypts its value.
// Returns (nil, nil) if the row doesn't exist or isn't a secret.
func (d *DB) GetSecret(id string) (*Secret, error) {
	row, err := d.q.GetSecretNode(context.Background(), id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query secret node: %w", err)
	}
	if row.Kind != string(KindSecret) {
		return nil, nil
	}
	plaintext, err := d.DecryptValue(row.Value)
	if err != nil {
		return nil, err
	}
	return &Secret{
		id:        row.ID,
		name:      row.Name,
		parentID:  ptrFromNullString(row.ParentID),
		Value:     plaintext,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

// GetNode fetches any node by ID and returns it as an ISecretNode.
// Returns (nil, nil) if not found. Groups come back without children
// populated — callers that need the full subtree should use LoadSubtree.
func (d *DB) GetNode(id string) (ISecretNode, error) {
	row, err := d.q.GetSecretNode(context.Background(), id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query node: %w", err)
	}
	return nodeFromRow(row, d)
}

// nodeFromRow converts a sqlc SecretNode row into an ISecretNode. For secret
// rows it decrypts the value; for group rows it returns an empty SecretGroup
// (children are populated separately).
func nodeFromRow(row sqlcdb.SecretNode, d *DB) (ISecretNode, error) {
	parent := ptrFromNullString(row.ParentID)
	switch NodeKind(row.Kind) {
	case KindSecret:
		plaintext, err := d.DecryptValue(row.Value)
		if err != nil {
			return nil, err
		}
		return &Secret{
			id:        row.ID,
			name:      row.Name,
			parentID:  parent,
			Value:     plaintext,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}, nil
	case KindGroup:
		return &SecretGroup{
			id:        row.ID,
			name:      row.Name,
			parentID:  parent,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}, nil
	default:
		return nil, fmt.Errorf("unknown node kind %q", row.Kind)
	}
}

// LoadSubtree loads every node at or below rootID (or every root node if
// rootID is nil) and assembles them into a tree of ISecretNodes. Secret
// values are decrypted so the returned *Secret.Value fields are plaintext.
// For a group root, returns a *SecretGroup whose Children() is populated
// recursively; for a secret root, returns the *Secret directly.
func (d *DB) LoadSubtree(rootID *string) ([]ISecretNode, error) {
	rows, err := d.q.ListAllNodes(context.Background())
	if err != nil {
		return nil, fmt.Errorf("list all nodes: %w", err)
	}
	return hydrateSubtree(rows, rootID, d)
}

// hydrateSubtree assembles a flat slice of sqlc SecretNode rows into a
// tree rooted at rootID (or the full root set when rootID is nil). It is
// the only place the flat-to-tree conversion logic lives; there is no
// repository method per navigation style.
func hydrateSubtree(rows []sqlcdb.SecretNode, rootID *string, d *DB) ([]ISecretNode, error) {
	nodesByID := make(map[string]ISecretNode, len(rows))
	for _, row := range rows {
		n, err := nodeFromRow(row, d)
		if err != nil {
			return nil, err
		}
		nodesByID[row.ID] = n
	}
	childrenByParent := make(map[string][]ISecretNode)
	var roots []ISecretNode
	for _, row := range rows {
		n := nodesByID[row.ID]
		if row.ParentID.Valid {
			childrenByParent[row.ParentID.String] = append(childrenByParent[row.ParentID.String], n)
		} else {
			roots = append(roots, n)
		}
	}
	// Attach children to groups.
	for _, row := range rows {
		if row.Kind != string(KindGroup) {
			continue
		}
		g := nodesByID[row.ID].(*SecretGroup)
		kids := childrenByParent[row.ID]
		sortNodes(kids)
		g.children = kids
	}
	sortNodes(roots)
	if rootID == nil {
		return roots, nil
	}
	n, ok := nodesByID[*rootID]
	if !ok {
		return nil, nil
	}
	return []ISecretNode{n}, nil
}

// sortNodes orders a node slice with groups first, then by name (stable).
func sortNodes(nodes []ISecretNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		_, iIsGroup := nodes[i].(*SecretGroup)
		_, jIsGroup := nodes[j].(*SecretGroup)
		if iIsGroup != jIsGroup {
			return iIsGroup
		}
		return nodes[i].Name() < nodes[j].Name()
	})
}

// UpdateSecretValue updates a secret leaf's encrypted value.
func (d *DB) UpdateSecretValue(id, plaintext string) error {
	enc, err := d.EncryptValue(plaintext)
	if err != nil {
		return err
	}
	res, err := d.q.UpdateSecretNodeValue(context.Background(), sqlcdb.UpdateSecretNodeValueParams{
		Value:     enc,
		UpdatedAt: time.Now().UTC(),
		ID:        id,
	})
	if err != nil {
		return fmt.Errorf("update secret value: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RenameNode renames any node (group or secret).
func (d *DB) RenameNode(id, name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	res, err := d.q.UpdateSecretNodeName(context.Background(), sqlcdb.UpdateSecretNodeNameParams{
		Name:      name,
		UpdatedAt: time.Now().UTC(),
		ID:        id,
	})
	if err != nil {
		return fmt.Errorf("rename node: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MoveNode changes a node's parent. newParentID may be nil to move to root.
func (d *DB) MoveNode(id string, newParentID *string) error {
	res, err := d.q.UpdateSecretNodeParent(context.Background(), sqlcdb.UpdateSecretNodeParentParams{
		ParentID:  nullStringFromPtr(newParentID),
		UpdatedAt: time.Now().UTC(),
		ID:        id,
	})
	if err != nil {
		return fmt.Errorf("move node: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNode removes a node. For groups this cascades to all descendants
// and to any policy attachments (via FK ON DELETE CASCADE).
func (d *DB) DeleteNode(id string) error {
	res, err := d.q.DeleteSecretNode(context.Background(), id)
	if err != nil {
		return fmt.Errorf("delete node: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// nullStringFromPtr converts a *string to a sql.NullString.
func nullStringFromPtr(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

// ptrFromNullString converts a sql.NullString to a *string.
func ptrFromNullString(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	s := n.String
	return &s
}
