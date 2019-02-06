package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	ecies "github.com/uniris/ecies/pkg"
)

func main() {

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(key.Public())

	tx := map[string]interface{}{
		"address":   "addr",
		"publicKey": hex.EncodeToString(pub),
		"timestamp": time.Now().Unix(),
		"type":      1,
		"data": map[string]string{
			"encrypted_Wallet": hex.EncodeToString([]byte("enc wallet")),
		},
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
	fullJSONEncrypted := generateEncrypedFullJSON(tx, key)
	fmt.Println(hex.EncodeToString(fullJSONEncrypted))
	fmt.Println(len(fullJSONEncrypted))
	t1End := time.Since(t1Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Encryption took %f seconds <==== \n", t1End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "ENCRYPT JSON FIELDS\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	t2Start := time.Now()
	JSONFieldsEncrypted := generateEncryptedJSONFields(tx, key)
	fmt.Println(string(JSONFieldsEncrypted))
	fmt.Println(len(JSONFieldsEncrypted))
	t2End := time.Since(t2Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Encryption took %f seconds <==== \n", t2End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "DECRYPT FULL JSON\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-----------------\n")
	t3Start := time.Now()
	decryptFullJSON(fullJSONEncrypted, key)
	t3End := time.Since(t3Start)
	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Decryption took %f seconds <==== \n", t3End.Seconds()))

	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	fmt.Printf("\033[1;36m%s\033[0m", "DECRYPT JSON FIELDS\n")
	fmt.Printf("\033[1;36m%s\033[0m", "-------------------\n")
	t4Start := time.Now()
	decryptJSONFields(JSONFieldsEncrypted, key)
	t4End := time.Since(t4Start)

	fmt.Printf("\033[1;33m%s\033[0m", fmt.Sprintf("====> Decryption took %f seconds <==== \n", t4End.Seconds()))
}

func generateEncrypedFullJSON(tx map[string]interface{}, key *ecdsa.PrivateKey) []byte {
	eciesPub := ecies.ImportECDSAPublic(key.Public().(*ecdsa.PublicKey))

	b, _ := json.Marshal(tx)
	cipherJSON, _ := ecies.Encrypt(rand.Reader, eciesPub, b, nil, nil)
	return cipherJSON
}

func generateEncryptedJSONFields(tx map[string]interface{}, pvKey *ecdsa.PrivateKey) []byte {
	eciesPub := ecies.ImportECDSAPublic(pvKey.Public().(*ecdsa.PublicKey))

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
			"encrypted_Wallet": hex.EncodeToString([]byte("enc wallet")),
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
	fmt.Println(tx)
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
