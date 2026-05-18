package checksum

import (
	"fmt"

	"github.com/rafinhacuri/crypt/crypt"
	"github.com/rafinhacuri/crypt/utils"
)

const tagSize = 4

// Append adiciona uma etiqueta de 32 bits ao final do conteudo original.
// Essa etiqueta ajuda a detectar chave errada ou arquivo alterado na decriptacao.
func Append(data []byte, keyText string) []byte {
	tag := Checksum(data, keyText)
	out := make([]byte, 0, len(data)+tagSize)
	out = append(out, data...)
	out = append(out, utils.Uint32ToBytes(tag)...)
	return out
}

// StripAndVerify remove a etiqueta e compara com o checksum recalculado.
func StripAndVerify(data []byte, keyText string) ([]byte, error) {
	if len(data) < tagSize {
		return nil, fmt.Errorf("texto claro sem etiqueta de verificacao")
	}

	content := data[:len(data)-tagSize]
	got := utils.BytesToUint32(data[len(data)-tagSize:])
	want := Checksum(content, keyText)
	if got != want {
		return nil, fmt.Errorf("etiqueta de verificacao invalida: chave incorreta ou arquivo alterado")
	}

	return content, nil
}

// Checksum calcula uma etiqueta simples de 32 bits usando dados e chave.
// Nao e uma funcao criptografica padrao; foi incluida para este projeto academico.
func Checksum(data []byte, keyText string) uint32 {
	value := crypt.MasterKey(keyText) ^ 0x811c9dc5 ^ uint32(len(data))
	for i, b := range data {
		value ^= uint32(b) + uint32(i+1)*0x01000193
		value = utils.Xorshift32(value)
		value += utils.RotateLeft32(value^0x9e3779b9, uint(i%31+1))
	}
	return value
}
