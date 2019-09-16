package tools

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	openpgperrors "golang.org/x/crypto/openpgp/errors"
)

var cmdName = path.Base(os.Args[0])

// Decrypt a file using the public key of the recipient
func Decrypt(privateKeyFileName string, readPass readPasswordCallback, publicKeyFileName string, file string) (err error) {

	if filepath.Ext(file) != ".pgp" {
		return fmt.Errorf("%s: filename to decrypt must end in .pgp", cmdName)
	}

	var signer openpgp.EntityList
	if signer, err = ReadPublicKeyFile(publicKeyFileName); err != nil {
		return err
	}

	var recipient *openpgp.Entity
	if recipient, err = ReadPrivateKeyFile(privateKeyFileName, readPass); err != nil {
		return err
	}
	if recipient == nil {
		return fmt.Errorf("%s: unable to read %s", privateKeyFileName)
	}

	var keyring openpgp.EntityList
	keyring = append(keyring, signer[0])
	keyring = append(keyring, recipient)

	var cipherTextFile *os.File
	if cipherTextFile, err = os.Open(file); err != nil {
		return err
	}
	defer cipherTextFile.Close()

	var cipherText io.Reader
	if p, err := armor.Decode(cipherTextFile); err == nil {
		cipherText = p.Body
	} else {
		if _, err = cipherTextFile.Seek(0, 0); err != nil {
			return err
		}
		cipherText = cipherTextFile
	}

	var md *openpgp.MessageDetails
	if md, err = openpgp.ReadMessage(cipherText, keyring, nil, nil); err != nil {
		return err
	}

	for _, recipients := range md.EncryptedToKeyIds {
		for _, key := range keyring.KeysById(recipients) {
			if key.Entity != nil {
				for k := range key.Entity.Identities {
					log.Println(k)
					// if v != nil {
					// 	log.Println(v.Name)
					// }
				}
			}
		}
	}

	var cwd string
	if cwd, err = os.Getwd(); err != nil {
		return err
	}
	var plainTextOutput *os.File
	if plainTextOutput, err = ioutil.TempFile(cwd, fmt.Sprintf(".%s.", cmdName)); err != nil {
		return err
	}
	var cleanExit bool
	defer func() {
		if !cleanExit {
			_ = os.Remove(plainTextOutput.Name())
		}
	}()

	_, err = io.Copy(plainTextOutput, md.UnverifiedBody)
	if err != nil {
		return err
	}
	plainTextOutput.Close()
	if md.SignatureError != nil {
		return md.SignatureError
	}
	if md.Signature == nil {
		return openpgperrors.ErrUnknownIssuer
	}

	bareFilename := strings.TrimSuffix(file, filepath.Ext(file))
	if len(md.LiteralData.FileName) != 0 && md.LiteralData.FileName != bareFilename {
		fmt.Fprintf(os.Stderr, "%s: suggested filename \"%s\"\n", cmdName, md.LiteralData.FileName)
	}
	var finalFilename string
	if _, err := os.Stat(bareFilename); os.IsNotExist(err) {
		finalFilename = bareFilename
	} else {
		finalFilename = fmt.Sprintf("%s.%X", bareFilename, uint32(md.SignedByKeyId&0xffffffff))
		fmt.Fprintf(os.Stderr, "%s: \"%s\" exists, writing to \"%s\"\n", cmdName, bareFilename, finalFilename)
	}

	err = os.Rename(plainTextOutput.Name(), finalFilename)
	if err == nil {
		cleanExit = true
	}
	return err
}
