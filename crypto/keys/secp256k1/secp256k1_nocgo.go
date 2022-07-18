//go:build !libsecp256k1_sdk
// +build !libsecp256k1_sdk

package secp256k1

import (
	"math/big"

	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/tendermint/tendermint/crypto"
)

// used to reject malleable signatures
// see:
//  - https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
//  - https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/crypto.go#L39
var secp256k1halfN = new(big.Int).Rsh(secp256k1.S256().N, 1)

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
// The returned signature will be of the form R || S (in lower-S form).
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	priv, _ := secp256k1.PrivKeyFromBytes(privKey.Key)
	// We use SignCompact just because it allows us to extract R and S from the result. We ignore the first byte of the signature (used to recover the public key)
	sig, err := btcecdsa.SignCompact(priv, crypto.Sha256(msg), false)
	if err != nil {
		return nil, err
	}
	return sig[1:], nil
}

// VerifyBytes verifies a signature of the form R || S.
// It rejects signatures which are not in lower-S form.
func (pubKey *PubKey) VerifySignature(msg []byte, sigStr []byte) bool {
	if len(sigStr) != 64 {
		return false
	}
	pub, err := secp256k1.ParsePubKey(pubKey.Key)
	if err != nil {
		return false
	}
	// parse the signature:
	signature := signatureFromBytes(sigStr)
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	// see: https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
	sBytes := signature.s.Bytes()
	s := new(big.Int).SetBytes(sBytes[:])
	if s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	return signature.Verify(crypto.Sha256(msg), pub)
}

// SignatureWithRS is necessary to make sure that when we pass around an instance of btcecdsa.Signature, we retain access to the raw R and S values and we can extract them back out to implement our own custom serialize method
type SignatureWithRS struct {
	*btcecdsa.Signature
	r *secp256k1.ModNScalar
	s *secp256k1.ModNScalar
}

// Read Signature struct from R || S. Caller needs to ensure
// that len(sigStr) == 64.
func signatureFromBytes(sigStr []byte) *SignatureWithRS {
	r := new(secp256k1.ModNScalar)
	r.SetByteSlice(sigStr[:32])
	s := new(secp256k1.ModNScalar)
	s.SetByteSlice(sigStr[32:64])
	return &SignatureWithRS{
		Signature: btcecdsa.NewSignature(r, s),
		r:         r,
		s:         s,
	}
}
