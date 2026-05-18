package crypt

import "github.com/rafinhacuri/crypt/utils"

// BuildSBox cria uma caixa de substituicao de 16 posicoes para nibbles.
// A ordem da tabela depende da subchave da rodada.
func BuildSBox(key uint32) [16]byte {
	var box [16]byte
	for i := range box {
		box[i] = byte(i)
	}

	seed := key ^ 0xc3a5c85c
	for i := len(box) - 1; i > 0; i-- {
		seed = utils.Xorshift32(seed + uint32(i)*0x27d4eb2d)
		j := int(seed % uint32(i+1))
		box[i], box[j] = box[j], box[i]
	}

	return box
}

// InvertSBox monta a tabela inversa, usada para desfazer a substituicao.
func InvertSBox(box [16]byte) [16]byte {
	var inverse [16]byte
	for i, value := range box {
		inverse[value] = byte(i)
	}
	return inverse
}

// SubstituteNibbles substitui cada grupo de 4 bits do bloco pela S-box.
func SubstituteNibbles(value uint32, box [16]byte) uint32 {
	var out uint32
	for shift := 0; shift < 32; shift += 4 {
		nibble := (value >> shift) & 0x0f
		out |= uint32(box[nibble]) << shift
	}
	return out
}
