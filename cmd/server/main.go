package main

import (
	"awesomeProject/pkg/transfer_protocol"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
)

// constantes
const AESKeySize = 32 // 256 bits

// Funcion encargada de manejar la conexion con el cliente
func handleConnection(conn net.Conn) {
	defer conn.Close() //se serciora de que la conexion se cierre si o si
	log.Printf("Conexion establecidad desde %s", conn.RemoteAddr().String())

	//Se crea la curva para la negociacion de clave Diffie-Hellman
	curve := elliptic.P256()

	sharedkey, err := negotiateKeyECDH(conn, curve)
	if err != nil {
		log.Printf("Error en la negociacion de la clave: %v", err)
		return
	}

	aeskey := sharedkey[:AESKeySize]

	log.Println("Se negocio con exito la clave AES-256")

	// Decodificacion del archivo cifrado
	var payload transfer_protocol.FileTransferPayload
	decoder := gob.NewDecoder(conn)
	if err := decoder.Decode(&payload); err != nil {
		log.Printf("Error al decodificarl el payload del archivo: %v", err)
	}

	log.Printf("Recibiendo archivo : %s. Tamaño de datos cifrados: %d bytes.", payload.FileName, len(payload.EncryptedData))

	// Proceso de descifrado del archivo
	decryptedData, err := decryptFile(payload, aeskey)
	if err != nil {
		log.Printf("Error en el descifrado: %v", err)
	}
	log.Println("Decifrado completado con exito")

	// Verificacion de la integridad con el SHA-256
	if err := verifyHash(decryptedData, payload.OriginalHash); err != nil {
		log.Printf("Error en la verificacion del hash: %v", err)
		fmt.Fprintf(conn, "TRANSFERENCIA FALLIDA: El hash calculado no coincide con el hash entregado por el cliente")
		return
	}

	log.Println("La verificacion del hash SHA-256 fue exitosa. La integridad del archivo esta confirmada")

	// Guardado del archivo descifrado
	if err := saveFile(payload.FileName, decryptedData); err != nil {
		log.Printf("Error al guardar el archivo: %v", err)
		fmt.Fprintf(conn, "TRANSFERENCIA EXITOSA, pero el servidor tuvo un error al tratar de guardar el archivo: %v", err)
		return
	}

	// Reportar la transferencia exitosa
	fmt.Fprintf(conn, "TRANSFERENCIA EXITOSA! El archivo '%s' se recibio y se valido el hash respecto al cliente", payload.FileName)
	log.Printf("Archivo '%s' fue guardado y verificado correctamente", payload.FileName)

}

// Funcion encargada de realizar el intercambio de claves para el  Elliptic Curve Diffie-Hellman (ECDH)
func negotiateKeyECDH(conn net.Conn, curve elliptic.Curve) ([]byte, error) {

	// El servidor genera un par de claves para el ECDH
	serverPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generar clave publica del servidor: %w", err)
	}

	// Proceso de envio de la clave publica del servidor
	serverPubKeyPayload := transfer_protocol.KeyExchangePayload{
		X: serverPrivateKey.PublicKey.X.Bytes(),
		Y: serverPrivateKey.PublicKey.Y.Bytes(),
	}
	encoder := gob.NewEncoder(conn)
	if err := encoder.Encode(serverPubKeyPayload); err != nil {
		return nil, fmt.Errorf("enviar clave publica del servidor: %w", err)
	}
	log.Println("Clave publica del servidor enviada")

	// Proceso de recepcion de clave publica del cliente
	var clientPublicKeyPayload transfer_protocol.KeyExchangePayload
	decoder := gob.NewDecoder(conn)
	if err := decoder.Decode(&clientPublicKeyPayload); err != nil {
		return nil, fmt.Errorf("recibit clave publica del cliente: %w", err)
	}
	clientPubKey := clientPublicKeyPayload.GetPublicKey(curve)
	if clientPubKey == nil || clientPubKey.X == nil {
		return nil, fmt.Errorf("clave publica del cliente no valida")
	}
	log.Println("La clave publica del cliente ha sido recibida")

	// Secuencia Para calcular el secreto compartido usando la clave privada del servidor y la clave publica del cliente
	sharedX, _ := curve.ScalarMult(clientPubKey.X, clientPubKey.Y, serverPrivateKey.D.Bytes())
	if sharedX == nil {
		return nil, fmt.Errorf("Error al calcular el secreto compartido")
	}

	h := sha256.Sum256(sharedX.Bytes())
	return h[:], nil
}

// decryptFile descifra los datos usando AES-256 GCM.
func decryptFile(payload transfer_protocol.FileTransferPayload, aeskey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aeskey)
	if err != nil {
		return nil, fmt.Errorf("Error al crear el bloque AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Error al crear el gcm: %w", err)
	}

	decryptedData, err := gcm.Open(nil, payload.Nonce, payload.EncryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("Error en la utenticación/descifrado GCM: %w", err)
	}

	return decryptedData, nil
}

func verifyHash(decryptedData, originalHash []byte) error {
	hasher := sha256.New()
	hasher.Write(decryptedData)
	calculatedHash := hasher.Sum(nil)

	if !equal(calculatedHash, originalHash) {
		return fmt.Errorf("El hash calculado del servidor (%x) NO COINCIDE con el hash enviado por el cliente (%x)", calculatedHash, originalHash)
	}
	return nil
}

// Funcion para verificacion de igualdad
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Funcion encargada de guardar el archivo en el la maquina del servidor
func saveFile(filename string, data []byte) error {
	receiveFilename := "RECEIVED_" + filename
	return os.WriteFile(receiveFilename, data, 0644)
}

func main() {
	// Inicio del registro de logs
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Iniciando el Servidor en el puerto %s ...", transfer_protocol.DefaultPort)

	// Inicio de la escucha del servidor por el puerto designado
	listener, err := net.Listen("tcp", transfer_protocol.DefaultPort)
	if err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
	defer listener.Close()
	fmt.Println("El servidor inicio con exito. Esperando conexiones ...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error al aceptar conexión: %v", err)
			continue
		}
		// Iniciar goroutine para manejar múltiples clientes
		go handleConnection(conn)
	}
}
