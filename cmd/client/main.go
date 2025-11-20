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
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
)

// Constantes
const AESKeySize = 32 // 256 bits

// Funcion para encriptar el archibo en base a la negociacion de claves.
func encryptFile(filename string, data, originalHash, aesKey []byte) (transfer_protocol.FileTransferPayload, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return transfer_protocol.FileTransferPayload{}, fmt.Errorf("Error al crear el bloque AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return transfer_protocol.FileTransferPayload{}, fmt.Errorf("Error al crear el GCM: %w", err)
	}

	//Crear un vector de inicializacion aleatoreo
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return transfer_protocol.FileTransferPayload{}, fmt.Errorf("Error al crear el vector de inicializacion: %w", err)
	}

	// Cifrado de loas datos y se añade la etiqueta de autenticacion
	encryptedData := gcm.Seal(nil, nonce, data, nil)

	// creacion del payload que se enviara
	payload := transfer_protocol.FileTransferPayload{
		FileName:      filepath.Base(filename),
		EncryptedData: encryptedData,
		Nonce:         nonce,
		OriginalHash:  originalHash,
	}
	return payload, nil
}

// Funccion para la negociacion de los parametros del Diffie-Hellman de curvas elipticas
func negotiateKeyECDH(conn net.Conn, curve elliptic.Curve) ([]byte, error) {
	// Generacion de la clave
	clientPrivKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Error al generar la clave pribada: %w", err)
	}

	//recepcion de la clave publica del servidor
	var serverPubKeyPayload transfer_protocol.KeyExchangePayload
	decoder := gob.NewDecoder(conn)
	if err := decoder.Decode(&serverPubKeyPayload); err != nil {
		return nil, fmt.Errorf("Error al recibir la clave publica del servidor: %w", err)
	}

	serverPubKey := serverPubKeyPayload.GetPublicKey(curve)
	if serverPubKey == nil || serverPubKey.X == nil {
		return nil, fmt.Errorf("Clave publica del servidor no valida")
	}

	log.Println("Clave publica del servidor recibida.")

	//calculo del secret
	sharedX, _ := curve.ScalarMult(serverPubKey.X, serverPubKey.Y, clientPrivKey.D.Bytes())
	if sharedX == nil {
		return nil, fmt.Errorf("Error en el calculo del secreto compartido")
	}

	//envio de clave publica del cliente al servidor
	clientPubKeyPayload := transfer_protocol.KeyExchangePayload{
		X: clientPrivKey.PublicKey.X.Bytes(),
		Y: clientPrivKey.PublicKey.Y.Bytes(),
	}
	encoder := gob.NewEncoder(conn)
	if err := encoder.Encode(&clientPubKeyPayload); err != nil {
		return nil, fmt.Errorf("Error al enviar la clave publica del cliente: %w", err)
	}

	log.Println("Clave publica del del cliente enviada.")

	h := sha256.Sum256(sharedX.Bytes())
	return h[:], nil
}

// Funcion encargada  de leer el archivo a enviar y calcular el hash SHA-256
func readFileAndHash(filename string) ([]byte, []byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("Error al leer el archivo: %w", err)
	}
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	return data, hash, nil
}

func main() {
	// Inicializacion del registro de logs
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Obtencion de datos desde la linea de comandos
	filenamePtr := flag.String("archivo", "", "Ruta del archivo a transferir")
	flag.Parse()

	if *filenamePtr == "" {
		fmt.Println("ERROR: debes especificar el nombre o ruta al archivo usando la bandera --archivo")
		flag.Usage()
		os.Exit(1)
	}

	// lectura del archivo y calculo del hash SHA-256
	fileData, originalHash, err := readFileAndHash(*filenamePtr)
	if err != nil {
		log.Fatal("Error en la lectura del archivo: %v", err)
	}
	log.Println("Archivo cargado: %s. Tamaño: %d bytes. Has SHA-256 calculado.", *filenamePtr, len(fileData))

	// Proceso de conexion al servidor
	log.Printf("Conectando al servidor en el puerto %s ...", transfer_protocol.DefaultPort)
	conn, err := net.Dial("tcp", transfer_protocol.DefaultPort)
	if err != nil {
		log.Fatal("No se pudo llevar a cabo la conexion con el servidor: %v", err)
	}
	defer conn.Close()
	log.Println("Conexion establecida con el servidor")

	// Negociacion de la clave Diffie-Hellman
	curve := elliptic.P256()
	sharedKey, err := negotiateKeyECDH(conn, curve)
	if err != nil {
		log.Fatal("Error en la negociacion de la clave: %v", err)
	}

	aesKey := sharedKey[:AESKeySize]
	log.Println("La clave AES-256 fue negociada con exito")

	// cifrado del archivo a enviar
	payload, err := encryptFile(*filenamePtr, fileData, originalHash, aesKey)

	if err != nil {
		log.Fatal("Error al cifrar el archivo: %v", err)
	}
	log.Println("Cifrado AES-256 GCM completado")

	// Enviar los datos al servidor
	encoder := gob.NewEncoder(conn)
	if err := encoder.Encode(&payload); err != nil {
		log.Fatal("Error al enviar el payload al servidor: %v", err)
	}
	log.Println("Payload del archivo cifrado y hash de integridad enviados. Esperando respuesta del servidor...")

	// Recepcion de respuesta del servidor
	response, err := io.ReadAll(conn)
	if err != nil {
		log.Fatal("Error al leer la respuesta del servidor: %v", err)
	}

	fmt.Printf("\n--- Respuesta del Servidor ---\n%s\n------------------------------\n", string(response))

}
