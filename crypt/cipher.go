package crypt

import "github.com/rafinhacuri/crypt/utils"

const (
	BlockSize = 4
	Rounds    = 8
)

type Cipher struct {
	subkeys [Rounds]uint32
}

type RoundStep struct {
	Round             int
	Subkey            uint32
	AfterXOR          uint32
	AfterKeyMix       uint32
	AfterSubstitution uint32
	AfterPermutation  uint32
}

func NewCipher(keyText string) Cipher {
	return Cipher{subkeys: DeriveSubkeys(keyText)}
}

// EncryptBlock cifra um bloco de 32 bits. Cada rodada mistura a subchave,
// aplica substituicao por nibbles dependente da chave e depois permuta os bits
// com uma tabela tambem derivada da subchave da rodada.
func (c Cipher) EncryptBlock(block uint32) uint32 {
	state := block
	for round := range Rounds {
		key := c.subkeys[round]
		state ^= key
		state += roundMix(key, round)
		state = SubstituteNibbles(state, BuildSBox(key))
		state = PermuteBits(state, BuildPermutation(key))
	}
	return state
}

func (c Cipher) TraceEncryptBlock(block uint32) []RoundStep {
	state := block
	steps := make([]RoundStep, 0, Rounds)

	for round := range Rounds {
		key := c.subkeys[round]
		afterXOR := state ^ key
		afterKeyMix := afterXOR + roundMix(key, round)
		afterSubstitution := SubstituteNibbles(afterKeyMix, BuildSBox(key))
		afterPermutation := PermuteBits(afterSubstitution, BuildPermutation(key))
		steps = append(steps, RoundStep{
			Round:             round + 1,
			Subkey:            key,
			AfterXOR:          afterXOR,
			AfterKeyMix:       afterKeyMix,
			AfterSubstitution: afterSubstitution,
			AfterPermutation:  afterPermutation,
		})
		state = afterPermutation
	}

	return steps
}

// DecryptBlock desfaz as rodadas na ordem inversa. A permutacao inversa,
// a S-box inversa e o XOR com a mesma subchave recuperam o bloco original.
func (c Cipher) DecryptBlock(block uint32) uint32 {
	state := block
	for round := Rounds - 1; round >= 0; round-- {
		key := c.subkeys[round]
		state = PermuteBits(state, InvertPermutation(BuildPermutation(key)))
		state = SubstituteNibbles(state, InvertSBox(BuildSBox(key)))
		state -= roundMix(key, round)
		state ^= key
	}
	return state
}

func roundMix(key uint32, round int) uint32 {
	return utils.RotateLeft32(key^0xa5a5a5a5, uint(round*5+3)) + uint32(round+1)*0x3c6ef372
}
