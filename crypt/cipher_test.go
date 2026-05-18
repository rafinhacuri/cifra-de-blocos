package crypt

import "testing"

func TestBlockRoundTrip(t *testing.T) {
	// Garante que um bloco cifrado pode ser decifrado para o valor original.
	cipher := NewCipher("inn-seguros")
	plain := uint32(0x41424344)
	encrypted := cipher.EncryptBlock(plain)
	decrypted := cipher.DecryptBlock(encrypted)

	if decrypted != plain {
		t.Fatalf("decrypted=%08x, want %08x", decrypted, plain)
	}
	if encrypted == plain {
		t.Fatal("encrypted block should differ from plaintext block")
	}
}

func TestTraceMatchesEncryptBlock(t *testing.T) {
	// O ultimo estado do trace deve ser igual ao resultado real da encriptacao.
	cipher := NewCipher("inn-seguros")
	steps := cipher.TraceEncryptBlock(0x494e4e21)
	last := steps[len(steps)-1].AfterPermutation

	if len(steps) != Rounds {
		t.Fatalf("len(steps)=%d, want %d", len(steps), Rounds)
	}
	if last != cipher.EncryptBlock(0x494e4e21) {
		t.Fatalf("trace final=%08x, encrypt=%08x", last, cipher.EncryptBlock(0x494e4e21))
	}
}

func TestSBoxInverse(t *testing.T) {
	// Aplica a S-box e depois sua inversa para confirmar que a substituicao e reversivel.
	box := BuildSBox(0x12345678)
	inverse := InvertSBox(box)
	value := uint32(0x89abcdef)

	got := SubstituteNibbles(SubstituteNibbles(value, box), inverse)
	if got != value {
		t.Fatalf("got %08x, want %08x", got, value)
	}
}

func TestPermutationInverse(t *testing.T) {
	// Aplica a permutacao e depois a inversa para confirmar que nenhum bit se perde.
	permutation := BuildPermutation(0x87654321)
	inverse := InvertPermutation(permutation)
	value := uint32(0xf0a55a0f)

	got := PermuteBits(PermuteBits(value, permutation), inverse)
	if got != value {
		t.Fatalf("got %08x, want %08x", got, value)
	}
}

func TestAvalancheWithOneBitKeyChange(t *testing.T) {
	// As chaves "A" e "@" diferem em 1 bit. O texto cifrado deve mudar bastante.
	block := uint32(0x494e4e21)
	first := NewCipher("A").EncryptBlock(block)
	second := NewCipher("@").EncryptBlock(block)
	distance := bitDistance(first, second)

	if distance < 10 {
		t.Fatalf("bit distance=%d, want at least 10", distance)
	}
}

func bitDistance(a, b uint32) int {
	// Conta quantos bits sao diferentes entre dois blocos de 32 bits.
	value := a ^ b
	count := 0
	for value != 0 {
		count += int(value & 1)
		value >>= 1
	}
	return count
}
