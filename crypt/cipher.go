package crypt

import "github.com/rafinhacuri/crypt/utils"

const (
	// BlockSize define o tamanho fixo de cada bloco da cifra: 4 bytes = 32 bits.
	BlockSize = 4
	// Rounds e maior que o minimo pedido para aumentar a difusao do algoritmo.
	Rounds = 8
)

type Cipher struct {
	// Cada rodada usa uma subchave diferente, derivada da chave textual.
	subkeys [Rounds]uint32
}

// RoundStep guarda os estados intermediarios usados pelo modo trace.
type RoundStep struct {
	Round             int
	Subkey            uint32
	AfterXOR          uint32
	AfterKeyMix       uint32
	AfterSubstitution uint32
	AfterPermutation  uint32
}

// NewCipher prepara a cifra gerando todas as subchaves antes do processamento.
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
		state ^= key                                      // mistura linear com a subchave
		state += roundMix(key, round)                     // mistura aritmetica reversivel
		state = SubstituteNibbles(state, BuildSBox(key))  // substituicao dependente da chave
		state = PermuteBits(state, BuildPermutation(key)) // permutacao dependente da chave
	}
	return state
}

// TraceEncryptBlock executa a mesma encriptacao, mas salva cada etapa.
// Isso facilita montar a tabela de rodadas exigida no documento tecnico.
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
		state = PermuteBits(state, InvertPermutation(BuildPermutation(key))) // desfaz a permutacao
		state = SubstituteNibbles(state, InvertSBox(BuildSBox(key)))         // desfaz a substituicao
		state -= roundMix(key, round)                                        // desfaz a mistura modular
		state ^= key                                                         // desfaz o XOR da rodada
	}
	return state
}

// roundMix cria uma constante de mistura da rodada. A soma e a subtracao dela
// sao reversiveis em uint32, por isso a decriptacao consegue desfazer a etapa.
func roundMix(key uint32, round int) uint32 {
	return utils.RotateLeft32(key^0xa5a5a5a5, uint(round*5+3)) + uint32(round+1)*0x3c6ef372
}
