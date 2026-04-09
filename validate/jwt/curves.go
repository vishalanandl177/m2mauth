package jwt

import (
	"crypto/elliptic"
)

// ellipticCurve is an alias for the standard elliptic.Curve interface.
type ellipticCurve = elliptic.Curve

func ellipticP256() elliptic.Curve { return elliptic.P256() }
func ellipticP384() elliptic.Curve { return elliptic.P384() }
func ellipticP521() elliptic.Curve { return elliptic.P521() }
