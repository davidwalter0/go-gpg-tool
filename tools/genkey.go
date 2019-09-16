package tools

import (
	"crypto"
	"errors"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

func lookup(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok || len(value) == 0 {
		log.Fatal("Env var ", key, " unset or empty")
	}
	return value
}

func entityData() (name string, comment string, email string) {
	name = lookup("KEY_USE_NAME")
	comment = lookup("KEY_USE_COMMENT")
	email = lookup("KEY_USE_EMAIL")
	return
}

func isExistingDirectory(p string) bool {
	s, err := os.Stat(p)
	if err != nil {
		return false
	}
	return s.Mode().IsDir()
}

func hashToHashId(h crypto.Hash) uint8 {
	v, ok := s2k.HashToHashId(h)
	if !ok {
		panic("tried to convert unknown hash")
	}
	return v
}

// GenerateKey in the path and file path
func GenerateKey(path string) (err error) {
	if len(path) == 0 {
		return errors.New("key file optional/dir/to/key/basename, basename must not be empty. ")
	}
	if isExistingDirectory(path) {
		return errors.New("key file optional/dir/to/key/basename, basename must not be empty. ")
	}

	var f *os.File
	var e *openpgp.Entity
	name, comment, email := entityData()
	// config := &packet.Config{DefaultHash: packet.SHA3_512, DefaultCipher: packet.CipherAES256, RSABits: 4096, CompressionAlgo: packet.BestSpeed}
	config := &packet.Config{RSABits: 4096, DefaultCompressionAlgo: packet.BestSpeed}
	e, err = openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return err
	}
	for _, id := range e.Identities {
		id.SelfSignature.PreferredSymmetric = []uint8{
			uint8(packet.CipherAES128),
			uint8(packet.CipherAES256),
			uint8(packet.CipherAES192),
			uint8(packet.CipherCAST5),
		}
		id.SelfSignature.PreferredHash = []uint8{
			hashToHashId(crypto.RIPEMD160),
			hashToHashId(crypto.SHA256),
			hashToHashId(crypto.SHA384),
			hashToHashId(crypto.SHA512),
			hashToHashId(crypto.SHA224),
			hashToHashId(crypto.MD5),
		}
		id.SelfSignature.PreferredCompression = []uint8{
			uint8(packet.CompressionNone),
		}
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return err
		}
	}

	f, err = os.Create(path + ".key.asc")
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	w, err := armor.Encode(f, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	e.SerializePrivate(w, nil)
	w.Close()
	f.Write([]byte{'\n'})

	f, err = os.Create(path + ".pub.asc")
	if err != nil {
		return err
	}
	defer f.Close()
	w, err = armor.Encode(f, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	e.Serialize(w)
	w.Close()
	f.Write([]byte{'\n'})

	return nil
}
