package crypt

import "github.com/rafinhacuri/crypt/utils"

// BuildPermutation cria uma permutacao dos 32 bits usando a subchave.
// A tabela indica para qual posicao cada bit de origem deve ir.
func BuildPermutation(key uint32) [32]byte {
	var permutation [32]byte
	for i := range permutation {
		permutation[i] = byte(i)
	}

	seed := key ^ 0x165667b1
	for i := len(permutation) - 1; i > 0; i-- {
		seed = utils.Xorshift32(seed + uint32(i)*0x85ebca6b)
		j := int(seed % uint32(i+1))
		permutation[i], permutation[j] = permutation[j], permutation[i]
	}

	return permutation
}

// InvertPermutation gera a tabela inversa para a etapa de decriptacao.
func InvertPermutation(permutation [32]byte) [32]byte {
	var inverse [32]byte
	for source, target := range permutation {
		inverse[target] = byte(source)
	}
	return inverse
}

// PermuteBits reposiciona os bits do bloco conforme a tabela informada.
func PermuteBits(value uint32, permutation [32]byte) uint32 {
	var out uint32
	for source := 0; source < 32; source++ {
		bit := (value >> source) & 1
		out |= bit << permutation[source]
	}
	return out
}
