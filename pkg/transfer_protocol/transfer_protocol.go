package transfer_protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

// Puerto que usa por defecto el servidor
const DefaultPort = ":8080"

// Type KeyExchangePayload contiene la clave publica (Uncamente las coordenadas X - Y) para el intercambio
type KeyExchangePayload struct {
	X, Y []byte
}

// Metodo que construye la clave publica a partir de las coordenadas X - Y
func (p *KeyExchangePayload) GetPublicKey(curve elliptic.Curve) *ecdsa.PublicKey {
	pubX := new(big.Int).SetBytes(p.X)
	pubY := new(big.Int).SetBytes(p.Y)

	if pubX.Sign() == 0 || pubY.Sign() == 0 || !curve.IsOnCurve(pubX, pubY) {
		return nil
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     pubX,
		Y:     pubY,
	}
}

// Type FileTransferPayload  contiene los datos necesarios para transferir el archivo
type FileTransferPayload struct {
	FileName      string
	EncryptedData []byte
	Nonce         []byte
	OriginalHash  []byte
}
