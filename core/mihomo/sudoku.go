package mihomo

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"github.com/metacubex/edwards25519"
)

// sudokuKeyDomain separates the user keys from any other use of a master key.
// Irboard derives the same keys for subscriptions (app/Protocols/Mihomo/
// SudokuKeys.php); a change here is a change there.
const sudokuKeyDomain = "irboard/sudoku/user-key/v1"

// sudokuMaster is a managed Sudoku node's master private key. A Sudoku server
// derives its tables and AEAD keys from the public key alone, and a client
// from the public key its split key sums to, so every user can hold their own
// split of the master; the hash of a split names the user.
type sudokuMaster struct {
	x      *edwards25519.Scalar
	public string // hex compressed point: the listener's key
}

func parseSudokuMaster(key string) (*sudokuMaster, error) {
	b, e := hex.DecodeString(key)
	if e != nil || len(b) != 32 {
		return nil, errors.New("sudoku key must be the 64-hex-digit master private key")
	}
	x, e := edwards25519.NewScalar().SetCanonicalBytes(b)
	if e != nil || x.Equal(edwards25519.NewScalar()) == 1 {
		return nil, errors.New("sudoku key is not a reduced, nonzero ed25519 scalar")
	}
	return &sudokuMaster{x: x, public: hex.EncodeToString(new(edwards25519.Point).ScalarBaseMult(x).Bytes())}, nil
}

// userKey is r || x-r, with r derived from the master and the user's UUID: a
// split of the master that only the panel, this node and that user know.
func (m *sudokuMaster) userKey(uuid string) string {
	h := sha512.New()
	h.Write([]byte(sudokuKeyDomain))
	h.Write([]byte{0})
	h.Write(m.x.Bytes())
	h.Write([]byte(uuid))
	r, _ := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	k := edwards25519.NewScalar().Subtract(m.x, r)
	return hex.EncodeToString(append(r.Bytes(), k.Bytes()...))
}

func (m *sudokuMaster) users(users map[string]*user) map[string]string {
	out := make(map[string]string, len(users))
	for name, u := range users {
		out[name] = m.userKey(u.uuid)
	}
	return out
}
