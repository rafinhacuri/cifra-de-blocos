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
	// fileMagic identifica arquivos produzidos por este programa.
	fileMagic            = []byte{'I', 'S', '3', '2'}
	errInvalidHeader     = errors.New("arquivo cifrado invalido: cabecalho ausente")
	errInvalidCiphertext = errors.New("arquivo cifrado invalido: tamanho dos blocos incorreto")
)

// EncryptFile le o arquivo original, cifra seu conteudo e grava o arquivo .is32.
func EncryptFile(inputPath, outputPath, keyText string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ler entrada: %w", err)
	}

	// O IV muda o primeiro bloco para que o mesmo arquivo possa gerar saidas
	// diferentes em execucoes diferentes com a mesma chave.
	iv := NewIV(keyText)
	ciphertext := EncryptCBC(data, keyText, iv)

	// Formato do arquivo: identificador IS32 + IV de 32 bits + blocos cifrados.
	output := make([]byte, 0, len(fileMagic)+crypt.BlockSize+len(ciphertext))
	output = append(output, fileMagic...)
	output = append(output, utils.Uint32ToBytes(iv)...)
	output = append(output, ciphertext...)

	if err := os.WriteFile(outputPath, output, 0600); err != nil {
		return fmt.Errorf("gravar saida: %w", err)
	}
	return nil
}

// DecryptFile le o arquivo cifrado, valida o cabecalho, decifra e grava o texto claro.
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

// ParseEncryptedFile separa o cabecalho, o IV e os blocos cifrados.
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

// NewIV gera um vetor inicial de 32 bits para o modo CBC.
func NewIV(keyText string) uint32 {
	seed := uint32(time.Now().UnixNano()) ^ crypt.MasterKey(keyText) ^ 0xd1b54a35
	return utils.Xorshift32(seed)
}

// EncryptCBC cifra dados de tamanho arbitrario em blocos de 32 bits.
// Antes de cifrar, adiciona checksum e padding para alinhar o tamanho.
func EncryptCBC(data []byte, keyText string, iv uint32) []byte {
	cipher := crypt.NewCipher(keyText)
	payload := checksum.Append(data, keyText)
	padded := padding.AddPadding(payload)
	out := make([]byte, 0, len(padded))
	previous := iv

	for start := 0; start < len(padded); start += crypt.BlockSize {
		block := utils.BytesToUint32(padded[start : start+crypt.BlockSize])
		// CBC: cada bloco claro e combinado com o cifrado anterior antes da cifra.
		encrypted := cipher.EncryptBlock(block ^ previous)
		out = append(out, utils.Uint32ToBytes(encrypted)...)
		previous = encrypted
	}

	return out
}

// DecryptCBC desfaz o encadeamento CBC, remove o padding e valida o checksum.
func DecryptCBC(data []byte, keyText string, iv uint32) ([]byte, error) {
	if len(data)%crypt.BlockSize != 0 {
		return nil, errInvalidCiphertext
	}

	cipher := crypt.NewCipher(keyText)
	padded := make([]byte, 0, len(data))
	previous := iv

	for start := 0; start < len(data); start += crypt.BlockSize {
		block := utils.BytesToUint32(data[start : start+crypt.BlockSize])
		// Na volta, decifra o bloco e depois aplica XOR com o bloco cifrado anterior.
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
