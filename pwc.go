package pwcrypto

import (
	"math/big"
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
