package filecrypt

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rafinhacuri/crypt/checksum"
	"github.com/rafinhacuri/crypt/crypt"
	"github.com/rafinhacuri/crypt/padding"
	"github.com/rafinhacuri/crypt/utils"
)

var (
	fileMagic            = []byte{'I', 'S', '3', '2'}
	errInvalidHeader     = errors.New("arquivo cifrado invalido: cabecalho ausente")
	errInvalidCiphertext = errors.New("arquivo cifrado invalido: tamanho dos blocos incorreto")
)

func EncryptFile(inputPath, outputPath, keyText string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ler entrada: %w", err)
	}

	iv := NewIV(keyText)
	ciphertext := EncryptCBC(data, keyText, iv)
	output := make([]byte, 0, len(fileMagic)+crypt.BlockSize+len(ciphertext))
	output = append(output, fileMagic...)
	output = append(output, utils.Uint32ToBytes(iv)...)
	output = append(output, ciphertext...)

	if err := os.WriteFile(outputPath, output, 0600); err != nil {
		return fmt.Errorf("gravar saida: %w", err)
	}
	return nil
}

func DecryptFile(inputPath, outputPath, keyText string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ler entrada: %w", err)
	}

	iv, ciphertext, err := ParseEncryptedFile(data)
	if err != nil {
		return err
	}

	plaintext, err := DecryptCBC(ciphertext, keyText, iv)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("gravar saida: %w", err)
	}
	return nil
}

func ParseEncryptedFile(data []byte) (uint32, []byte, error) {
	if len(data) < len(fileMagic)+crypt.BlockSize {
		return 0, nil, errInvalidHeader
	}
	for i := range fileMagic {
		if data[i] != fileMagic[i] {
			return 0, nil, errInvalidHeader
		}
	}

	ivStart := len(fileMagic)
	ivEnd := ivStart + crypt.BlockSize
	ciphertext := data[ivEnd:]
	if len(ciphertext) == 0 || len(ciphertext)%crypt.BlockSize != 0 {
		return 0, nil, errInvalidCiphertext
	}

	return utils.BytesToUint32(data[ivStart:ivEnd]), ciphertext, nil
}

func NewIV(keyText string) uint32 {
	seed := uint32(time.Now().UnixNano()) ^ crypt.MasterKey(keyText) ^ 0xd1b54a35
	return utils.Xorshift32(seed)
}

func EncryptCBC(data []byte, keyText string, iv uint32) []byte {
	cipher := crypt.NewCipher(keyText)
	payload := checksum.Append(data, keyText)
	padded := padding.AddPadding(payload)
	out := make([]byte, 0, len(padded))
	previous := iv

	for start := 0; start < len(padded); start += crypt.BlockSize {
		block := utils.BytesToUint32(padded[start : start+crypt.BlockSize])
		encrypted := cipher.EncryptBlock(block ^ previous)
		out = append(out, utils.Uint32ToBytes(encrypted)...)
		previous = encrypted
	}

	return out
}

func DecryptCBC(data []byte, keyText string, iv uint32) ([]byte, error) {
	if len(data)%crypt.BlockSize != 0 {
		return nil, errInvalidCiphertext
	}

	cipher := crypt.NewCipher(keyText)
	padded := make([]byte, 0, len(data))
	previous := iv

	for start := 0; start < len(data); start += crypt.BlockSize {
		block := utils.BytesToUint32(data[start : start+crypt.BlockSize])
		decrypted := cipher.DecryptBlock(block) ^ previous
		padded = append(padded, utils.Uint32ToBytes(decrypted)...)
		previous = block
	}

	payload, err := padding.RemovePadding(padded)
	if err != nil {
		return nil, err
	}

	return checksum.StripAndVerify(payload, keyText)
}
