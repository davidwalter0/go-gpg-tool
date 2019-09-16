package tools

import (
	"fmt"
	"io"
	"os"
	"path"

	"golang.org/x/crypto/openpgp"
	_ "golang.org/x/crypto/ripemd160"
)

func EncryptSign(privateKeyFileName string, readPass readPasswordCallback, publicKeyFileName string, plainTextFile string, cipherTextFile string) (err error) {

	var signer *openpgp.Entity
	if signer, err = ReadPrivateKeyFile(privateKeyFileName, readPass); err != nil {
		return err
	}

	var recipients openpgp.EntityList
	if recipients, err = ReadPublicKeyFile(publicKeyFileName); err != nil {
		return err
	}

	var plainTextInput *os.File
	if plainTextInput, err = os.Open(plainTextFile); err != nil {
		return err
	}
	defer plainTextInput.Close()

	inputStat, err := plainTextInput.Stat()
	if err != nil {
		return err
	}
	plainTextBytes := inputStat.Size()

	var cipherTextOutput *os.File
	if cipherTextOutput, err = os.Create(cipherTextFile); err != nil {
		return err
	}

	fHints := &openpgp.FileHints{
		IsBinary: true,
		FileName: path.Base(plainTextFile),
		ModTime:  inputStat.ModTime(),
	}

	var we io.WriteCloser
	if we, err = openpgp.Encrypt(cipherTextOutput, recipients, signer, fHints, nil); err != nil {
		return err
	}
	defer we.Close()

	copiedBytes, err := io.Copy(we, plainTextInput)
	if copiedBytes != plainTextBytes {
		return fmt.Errorf("encrypted only %d bytes out of %d", copiedBytes, plainTextBytes)
	}
	return nil
}
