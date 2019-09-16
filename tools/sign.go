package tools

import (
	"os"

	"golang.org/x/crypto/openpgp"
)

// Sign file with private key
func Sign(privateKeyFileName string, readPass readPasswordCallback, fileToSign string, signatureFile string) (err error) {

	var signer *openpgp.Entity
	if signer, err = ReadPrivateKeyFile(privateKeyFileName, readPass); err != nil {
		return err
	}

	var message *os.File
	if message, err = os.Open(fileToSign); err != nil {
		return err
	}
	defer message.Close()

	var w *os.File
	if w, err = os.Create(signatureFile); err != nil {
		return err
	}
	defer w.Close()

	if err = openpgp.ArmoredDetachSign(w, signer, message, nil); err != nil {
		return err
	}
	w.Write([]byte("\n"))

	return nil
}
