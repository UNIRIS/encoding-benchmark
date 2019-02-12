package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	ecies "github.com/uniris/ecies/pkg"
	"golang.org/x/crypto/pbkdf2"
)

func main() {

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(key.Public())

	tx := map[string]interface{}{
		"address":   "addr",
		"publicKey": hex.EncodeToString(pub),
		"timestamp": time.Now().Unix(),
		"type":      1,
		"data":      map[string]string{},
	}
	bTx, _ := json.Marshal(tx)
	r, s, _ := ecdsa.Sign(rand.Reader, key, []byte(bTx))
	sig, _ := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
		R: r,
		S: s,
	})

	tx["signature"] = hex.EncodeToString(sig)
	tx["em_signature"] = hex.EncodeToString(sig)

	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "ENCRYPT FULL JSON\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")

	t1Start := time.Now()
	fullJSONEncrypted := generateEncryptedFullJSON(tx, key)
	fmt.Println(hex.EncodeToString(fullJSONEncrypted))
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Length %d bytes <==== \n", len(fullJSONEncrypted)))
	t1End := time.Since(t1Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Encryption took %f seconds <==== \n", t1End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "ENCRYPT FULL JSON COMPRESSED\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")

	t2Start := time.Now()
	fullJSONCompressedEncrypted := generateCompressedEncryptedFullJSON(tx, key)
	fmt.Println(hex.EncodeToString(fullJSONCompressedEncrypted))
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Length %d bytes <==== \n", len(fullJSONCompressedEncrypted)))
	t2End := time.Since(t2Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Encryption took %f seconds <==== \n", t2End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "ENCRYPT JSON FIELDS\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	t3Start := time.Now()
	JSONFieldsEncrypted := generateEncryptedJSONFields(tx, key)
	fmt.Println(string(JSONFieldsEncrypted))
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Length %d bytes <==== \n", len(JSONFieldsEncrypted)))
	t3End := time.Since(t3Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Encryption took %f seconds <==== \n", t3End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "ENCRYPT JSON FIELDS COMPRESSED\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	t4Start := time.Now()
	JSONCompressedFieldsEncrypted := generateCompressedEncryptedJSONFields(tx, key)
	fmt.Println(string(JSONFieldsEncrypted))
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Length %d bytes <==== \n", len(JSONCompressedFieldsEncrypted)))
	t4End := time.Since(t4Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Encryption took %f seconds <==== \n", t4End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "DECRYPT FULL JSON\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	t5Start := time.Now()
	decryptFullJSON(fullJSONEncrypted, key)
	t5End := time.Since(t5Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Decryption took %f seconds <==== \n", t5End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "DECRYPT FULL JSON COMPRESSED\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	t6Start := time.Now()
	decryptCompressedFullJSON(fullJSONCompressedEncrypted, key)
	t6End := time.Since(t6Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Decryption took %f seconds <==== \n", t6End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "DECRYPT JSON FIELDS\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	t7Start := time.Now()
	decryptJSONFields(JSONFieldsEncrypted, key)
	t7End := time.Since(t7Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Decryption took %f seconds <==== \n", t7End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "DECRYPT JSON FIELDS COMPRESSED\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	t8Start := time.Now()
	decryptCompressJSONFields(JSONCompressedFieldsEncrypted, key)
	t8End := time.Since(t8Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Decryption took %f seconds <==== \n", t8End.Seconds()))
}

func generateEncryptedFullJSON(tx map[string]interface{}, key *ecdsa.PrivateKey) []byte {
	encWallet := symEncrypt(generateWallet())
	tx["data"] = map[string]string{
		"encrypted_wallet": hex.EncodeToString(encWallet),
	}

	eciesPub := ecies.ImportECDSAPublic(key.Public().(*ecdsa.PublicKey))

	b, _ := json.Marshal(tx)
	cipherJSON, _ := ecies.Encrypt(rand.Reader, eciesPub, b, nil, nil)
	return cipherJSON
}

func generateCompressedEncryptedFullJSON(tx map[string]interface{}, key *ecdsa.PrivateKey) []byte {
	w := generateWallet()
	wComp := compress(w)

	encWallet := symEncrypt(wComp)
	tx["data"] = map[string]string{
		"encrypted_wallet": hex.EncodeToString(encWallet),
	}

	b, _ := json.Marshal(tx)

	comp := compress(b)

	eciesPub := ecies.ImportECDSAPublic(key.Public().(*ecdsa.PublicKey))
	cipherJSON, _ := ecies.Encrypt(rand.Reader, eciesPub, comp, nil, nil)
	return cipherJSON
}

func generateEncryptedJSONFields(tx map[string]interface{}, pvKey *ecdsa.PrivateKey) []byte {
	eciesPub := ecies.ImportECDSAPublic(pvKey.Public().(*ecdsa.PublicKey))

	encWallet := symEncrypt(generateWallet())

	cipherAddr, _ := ecies.Encrypt(rand.Reader, eciesPub, []byte(tx["address"].(string)), nil, nil)
	cipherPublickey, _ := ecies.Encrypt(rand.Reader, eciesPub, []byte(tx["publicKey"].(string)), nil, nil)
	cipherTimestamp, _ := ecies.Encrypt(rand.Reader, eciesPub, []byte(strconv.Itoa(int(tx["timestamp"].(int64)))), nil, nil)
	cipherType, _ := ecies.Encrypt(rand.Reader, eciesPub, []byte(strconv.Itoa(tx["type"].(int))), nil, nil)
	cipherSig, _ := ecies.Encrypt(rand.Reader, eciesPub, []byte(tx["signature"].(string)), nil, nil)
	cipherEmSig, _ := ecies.Encrypt(rand.Reader, eciesPub, []byte(tx["em_signature"].(string)), nil, nil)

	tx = map[string]interface{}{
		"address":   hex.EncodeToString(cipherAddr),
		"publicKey": hex.EncodeToString(cipherPublickey),
		"timestamp": hex.EncodeToString(cipherTimestamp),
		"type":      hex.EncodeToString(cipherType),
		"data": map[string]string{
			"encrypted_wallet": hex.EncodeToString(encWallet),
		},
		"signature":    hex.EncodeToString(cipherSig),
		"em_signature": hex.EncodeToString(cipherEmSig),
	}

	bTx, _ := json.Marshal(tx)
	return bTx
}

func generateCompressedEncryptedJSONFields(tx map[string]interface{}, pvKey *ecdsa.PrivateKey) []byte {
	eciesPub := ecies.ImportECDSAPublic(pvKey.Public().(*ecdsa.PublicKey))

	compAddr := compress([]byte(tx["address"].(string)))
	compPublickey := compress([]byte(tx["publicKey"].(string)))
	compTimestamp := compress([]byte(strconv.Itoa(int(tx["timestamp"].(int64)))))
	compType := compress([]byte(strconv.Itoa(tx["type"].(int))))
	compSig := compress([]byte(tx["signature"].(string)))
	compEmSig := compress([]byte(tx["em_signature"].(string)))

	w := generateWallet()
	wComp := compress(w)

	encWallet := symEncrypt(wComp)

	cipherAddr, _ := ecies.Encrypt(rand.Reader, eciesPub, compAddr, nil, nil)
	cipherPublickey, _ := ecies.Encrypt(rand.Reader, eciesPub, compPublickey, nil, nil)
	cipherTimestamp, _ := ecies.Encrypt(rand.Reader, eciesPub, compTimestamp, nil, nil)
	cipherType, _ := ecies.Encrypt(rand.Reader, eciesPub, compType, nil, nil)
	cipherSig, _ := ecies.Encrypt(rand.Reader, eciesPub, compSig, nil, nil)
	cipherEmSig, _ := ecies.Encrypt(rand.Reader, eciesPub, compEmSig, nil, nil)

	tx = map[string]interface{}{
		"address":   hex.EncodeToString(cipherAddr),
		"publicKey": hex.EncodeToString(cipherPublickey),
		"timestamp": hex.EncodeToString(cipherTimestamp),
		"type":      hex.EncodeToString(cipherType),
		"data": map[string]string{
			"encrypted_wallet": hex.EncodeToString(encWallet),
		},
		"signature":    hex.EncodeToString(cipherSig),
		"em_signature": hex.EncodeToString(cipherEmSig),
	}

	bTx, _ := json.Marshal(tx)
	return bTx
}

func decryptFullJSON(cipher []byte, pvKey *ecdsa.PrivateKey) {
	eciesKey := ecies.ImportECDSA(pvKey)
	decipher, _ := eciesKey.Decrypt(cipher, nil, nil)
	tx := make(map[string]interface{})
	json.Unmarshal(decipher, &tx)
	b, _ := json.Marshal(tx)
	fmt.Println(string(b))
}

func decryptCompressedFullJSON(cipher []byte, pvKey *ecdsa.PrivateKey) {
	eciesKey := ecies.ImportECDSA(pvKey)
	decipher, _ := eciesKey.Decrypt(cipher, nil, nil)

	txBytes := decompress(decipher)
	tx := make(map[string]interface{})
	json.Unmarshal(txBytes, &tx)

	b, _ := json.Marshal(tx)
	fmt.Println(string(b))
}

func decryptJSONFields(jsonBytes []byte, pvKey *ecdsa.PrivateKey) {

	eciesKey := ecies.ImportECDSA(pvKey)

	tx := make(map[string]interface{})
	json.Unmarshal(jsonBytes, &tx)

	cipherAddr := tx["address"].(string)
	cipherPubKey := tx["publicKey"].(string)
	cipherTimestamp := tx["timestamp"].(string)
	cipherType := tx["type"].(string)
	cipherSignature := tx["signature"].(string)
	cipherEmSignature := tx["em_signature"].(string)

	addrB, _ := hex.DecodeString(cipherAddr)
	pubkB, _ := hex.DecodeString(cipherPubKey)
	timestampB, _ := hex.DecodeString(cipherTimestamp)
	typeB, _ := hex.DecodeString(cipherType)
	sigB, _ := hex.DecodeString(cipherSignature)
	emSigB, _ := hex.DecodeString(cipherEmSignature)

	clearAddr, _ := eciesKey.Decrypt(addrB, nil, nil)
	publicKey, _ := eciesKey.Decrypt(pubkB, nil, nil)
	timestamp, _ := eciesKey.Decrypt(timestampB, nil, nil)
	txType, _ := eciesKey.Decrypt(typeB, nil, nil)
	sig, _ := eciesKey.Decrypt(sigB, nil, nil)
	emSig, _ := eciesKey.Decrypt(emSigB, nil, nil)

	fmt.Printf("address: %s\n", clearAddr)
	fmt.Printf("publicKey: %s\n", publicKey)
	fmt.Printf("timestamp: %s\n", timestamp)
	fmt.Printf("type: %s\n", txType)
	fmt.Printf("signature: %s\n", sig)
	fmt.Printf("emitter signature: %s\n", emSig)
}

func decryptCompressJSONFields(jsonBytes []byte, pvKey *ecdsa.PrivateKey) {
	eciesKey := ecies.ImportECDSA(pvKey)

	tx := make(map[string]interface{})
	json.Unmarshal(jsonBytes, &tx)

	cipherAddr := tx["address"].(string)
	cipherPubKey := tx["publicKey"].(string)
	cipherTimestamp := tx["timestamp"].(string)
	cipherType := tx["type"].(string)
	cipherSignature := tx["signature"].(string)
	cipherEmSignature := tx["em_signature"].(string)

	addrB, _ := hex.DecodeString(cipherAddr)
	pubkB, _ := hex.DecodeString(cipherPubKey)
	timestampB, _ := hex.DecodeString(cipherTimestamp)
	typeB, _ := hex.DecodeString(cipherType)
	sigB, _ := hex.DecodeString(cipherSignature)
	emSigB, _ := hex.DecodeString(cipherEmSignature)

	compClearAddr, _ := eciesKey.Decrypt(addrB, nil, nil)
	compPublicKey, _ := eciesKey.Decrypt(pubkB, nil, nil)
	compTimestamp, _ := eciesKey.Decrypt(timestampB, nil, nil)
	compTxType, _ := eciesKey.Decrypt(typeB, nil, nil)
	compSig, _ := eciesKey.Decrypt(sigB, nil, nil)
	compEmSig, _ := eciesKey.Decrypt(emSigB, nil, nil)

	fmt.Printf("address: %s\n", decompress(compClearAddr))
	fmt.Printf("publicKey: %s\n", decompress(compPublicKey))
	fmt.Printf("timestamp: %s\n", decompress(compTimestamp))
	fmt.Printf("type: %s\n", decompress(compTxType))
	fmt.Printf("signature: %s\n", decompress(compSig))
	fmt.Printf("emitter signature: %s\n", decompress(compEmSig))
}

func generateWallet() []byte {
	keyUniris, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvUniris, _ := x509.MarshalECPrivateKey(keyUniris)

	keyGmail, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvGmail, _ := x509.MarshalECPrivateKey(keyGmail)

	keyEthereum, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvEthereum, _ := x509.MarshalECPrivateKey(keyEthereum)

	w := map[string]interface{}{
		"services": map[string]interface{}{
			"uniris": map[string]string{
				"key": hex.EncodeToString(pvUniris),
			},
			"gmail": map[string]string{
				"key": hex.EncodeToString(pvGmail),
			},
			"ethereum": map[string]string{
				"key": hex.EncodeToString(pvEthereum),
			},
		},
	}

	walletJSON, _ := json.Marshal(w)

	return walletJSON
}

func compress(data []byte) []byte {
	var buf bytes.Buffer
	g := gzip.NewWriter(&buf)
	g.Write(data)
	g.Flush()
	g.Close()
	return buf.Bytes()
}

func decompress(data []byte) []byte {
	buf := bytes.NewReader(data)
	r, _ := gzip.NewReader(buf)
	s, _ := ioutil.ReadAll(r)
	return s
}

func symEncrypt(data []byte) []byte {
	hash := sha256.New

	//Generate salt
	salt := make([]byte, hash().Size())
	io.ReadFull(rand.Reader, salt)

	//Generate a key from the salt and the secret
	derivedKey := pbkdf2.Key([]byte("my super passphrase"), salt, 100000, 16, hash)
	c, _ := aes.NewCipher(derivedKey)
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	cipher := gcm.Seal(nonce, nonce, data, nil)
	return cipher
}
