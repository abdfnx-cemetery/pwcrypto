package pwcrypto

import (
	"fmt"
	"errors"
	"math/big"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"crypto/elliptic"

	"github.com/tscholl2/siec"
)

type EllipticCurve interface {
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	IsOnCurve(x, y *big.Int) bool
}

type PWCrypto struct {
	// Public variables
	Role   int
	Uᵤ, Uᵥ *big.Int
	Vᵤ, Vᵥ *big.Int
	Xᵤ, Xᵥ *big.Int
	Yᵤ, Yᵥ *big.Int

	// Private variables
	curve      EllipticCurve
	Pw         []byte
	Vpwᵤ, Vpwᵥ *big.Int
	Upwᵤ, Upwᵥ *big.Int
	Aα         []byte
	Aαᵤ, Aαᵥ   *big.Int
	Zᵤ, Zᵥ     *big.Int
	K          []byte
}

// Public returns the public variables of PWCrypto
func (p *PWCrypto) Public() *PWCrypto {
	return &PWCrypto{
		Role: p.Role,
		Uᵤ:   p.Uᵤ,
		Uᵥ:   p.Uᵥ,
		Vᵤ:   p.Vᵤ,
		Vᵥ:   p.Vᵥ,
		Xᵤ:   p.Xᵤ,
		Xᵥ:   p.Xᵥ,
		Yᵤ:   p.Yᵤ,
		Yᵥ:   p.Yᵥ,
	}
}

// AvailableCurves returns available curves
func AvailableCurves() []string {
	return []string{"p521", "p256", "p384", "siec"}
}

// InitCurve will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be siec,  p521, p256, p384
func initCurve(curve string) (ellipticCurve EllipticCurve, Ux *big.Int, Uy *big.Int, Vx *big.Int, Vy *big.Int, err error) {
	switch curve {
		case "p521":
			ellipticCurve = elliptic.P521()
			Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
			Uy, _ = new(big.Int).SetString("4032821203812196944795502391345776760852202059010382256134592838722123385325802540879231526503456158741518531456199762365161310489884151533417829496019094620", 10)
			Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
			Vy, _ = new(big.Int).SetString("5010916268086655347194655708160715195931018676225831839835602465999566066450501167246678404591906342753230577187831311039273858772817427392089150297708931207", 10)

		case "p256":
			ellipticCurve = elliptic.P256()
			Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
			Uy, _ = new(big.Int).SetString("59748757929350367369315811184980635230185250460108398961713395032485227207304", 10)
			Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
			Vy, _ = new(big.Int).SetString("9157340230202296554417312816309453883742349874205386245733062928888341584123", 10)

		case "p384":
			ellipticCurve = elliptic.P384()
			Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
			Uy, _ = new(big.Int).SetString("7854890799382392388170852325516804266858248936799429260403044177981810983054351714387874260245230531084533936948596", 10)
			Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
			Vy, _ = new(big.Int).SetString("21898206562669911998235297167979083576432197282633635629145270958059347586763418294901448537278960988843108277491616", 10)

		case "siec":
			ellipticCurve = siec.SIEC255()
			Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671853", 10)
			Uy, _ = new(big.Int).SetString("18458907634222644275952014841865282643645472623913459400556233196838128612339", 10)
			Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
			Vy, _ = new(big.Int).SetString("19593504966619549205903364028255899745298716108914514072669075231742699650911", 10)

		default:
			err = errors.New("no such curve")
			return
	}

	return
}

// Init will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be any elliptic curve.
func InitCurve(pw []byte, role int, curve string) (p *PWCrypto, err error) {
	p = new(PWCrypto)
	p.curve, p.Uᵤ, p.Uᵥ, p.Vᵤ, p.Vᵥ, err = initCurve(curve)

	if err != nil {
		return
	}

	p.Pw = pw

	if role == 1 {
		p.Role = 1
	} else {
		p.Role = 0

		// STEP: A computes X
		p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.Pw)
		p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.Pw)
		p.Aα = make([]byte, 32) // randomly generated secret
		_, err = rand.Read(p.Aα)
		if err != nil {
			return
		}

		p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
		p.Xᵤ, p.Xᵥ = p.curve.Add(p.Upwᵤ, p.Upwᵥ, p.Aαᵤ, p.Aαᵥ) // "X"
	}

	return
}

// Bytes just marshalls the PAKE structure so that
// private variables are hidden.
func (p *PWCrypto) Bytes() (b []byte) {
	if p == nil {
		panic("pwc is not initialized")
	}

	b, err := json.Marshal(p.Public())
	if err != nil {
		panic(err)
	}

	return
}

// Update will update itself with the other parties
// PAKE and automatically determine what stage
// and what to generate.
func (p *PWCrypto) Update(qBytes []byte) (err error) {
	if p == nil {
		err = fmt.Errorf("pwc is not initialized")
		return
	}

	var q *PWCrypto
	err = json.Unmarshal(qBytes, &q)
	if err != nil {
		return
	}

	if p.Role == q.Role {
		err = errors.New("can't have its own role")
		return
	}

	if p.Role == 1 {
		// copy over public variables
		p.Xᵤ, p.Xᵥ = q.Xᵤ, q.Xᵥ

		// confirm that X is on curve
		if !p.curve.IsOnCurve(p.Xᵤ, p.Xᵥ) {
			err = errors.New("X values not on curve")
			return
		}

		// STEP: B computes Y
		p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.Pw)
		p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.Pw)
		p.Aα = make([]byte, 32) // randomly generated secret
		rand.Read(p.Aα)
		p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
		p.Yᵤ, p.Yᵥ = p.curve.Add(p.Vpwᵤ, p.Vpwᵥ, p.Aαᵤ, p.Aαᵥ) // "Y"
		// STEP: B computes Z
		p.Zᵤ, p.Zᵥ = p.curve.Add(p.Xᵤ, p.Xᵥ, p.Upwᵤ, new(big.Int).Neg(p.Upwᵥ))
		p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
		// STEP: B computes k
		// H(pw,id_P,id_Q,X,Y,Z)
		HB := sha256.New()
		HB.Write(p.Pw)
		HB.Write(p.Xᵤ.Bytes())
		HB.Write(p.Xᵥ.Bytes())
		HB.Write(p.Yᵤ.Bytes())
		HB.Write(p.Yᵥ.Bytes())
		HB.Write(p.Zᵤ.Bytes())
		HB.Write(p.Zᵥ.Bytes())
		// STEP: B computes k
		p.K = HB.Sum(nil)
	} else {
		p.Yᵤ, p.Yᵥ = q.Yᵤ, q.Yᵥ

		// confirm that Y is on curve
		if !p.curve.IsOnCurve(p.Yᵤ, p.Yᵥ) {
			err = errors.New("Y values not on curve")
			return
		}

		// STEP: A computes Z
		p.Zᵤ, p.Zᵥ = p.curve.Add(p.Yᵤ, p.Yᵥ, p.Vpwᵤ, new(big.Int).Neg(p.Vpwᵥ))
		p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
		// STEP: A computes k
		// H(pw,id_P,id_Q,X,Y,Z)
		HA := sha256.New()
		HA.Write(p.Pw)
		HA.Write(p.Xᵤ.Bytes())
		HA.Write(p.Xᵥ.Bytes())
		HA.Write(p.Yᵤ.Bytes())
		HA.Write(p.Yᵥ.Bytes())
		HA.Write(p.Zᵤ.Bytes())
		HA.Write(p.Zᵥ.Bytes())

		p.K = HA.Sum(nil)
	}

	return
}

// SessionKey is returned, unless it is not generated
// in which is returns an error. This function does
// not check if it is verifies.
func (p *PWCrypto) SessionKey() ([]byte, error) {
	var err error
	if p == nil {
		err = fmt.Errorf("pwc is not initialized")
	}

	if p.K == nil {
		err = errors.New("session key not generated")
	}

	return p.K, err
}

// HaveSessionKey returns whether a session key has been generated
func (p *PWCrypto) HaveSessionKey() bool {
	if p == nil {
		return false
	}

	return p.K != nil
}
