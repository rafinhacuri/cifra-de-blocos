package crypt

import "testing"

func TestBlockRoundTrip(t *testing.T) {
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
	box := BuildSBox(0x12345678)
	inverse := InvertSBox(box)
	value := uint32(0x89abcdef)

	got := SubstituteNibbles(SubstituteNibbles(value, box), inverse)
	if got != value {
		t.Fatalf("got %08x, want %08x", got, value)
	}
}

func TestPermutationInverse(t *testing.T) {
	permutation := BuildPermutation(0x87654321)
	inverse := InvertPermutation(permutation)
	value := uint32(0xf0a55a0f)

	got := PermuteBits(PermuteBits(value, permutation), inverse)
	if got != value {
		t.Fatalf("got %08x, want %08x", got, value)
	}
}

func TestAvalancheWithOneBitKeyChange(t *testing.T) {
	block := uint32(0x494e4e21)
	first := NewCipher("A").EncryptBlock(block)
	second := NewCipher("@").EncryptBlock(block)
	distance := bitDistance(first, second)

	if distance < 10 {
		t.Fatalf("bit distance=%d, want at least 10", distance)
	}
}

func bitDistance(a, b uint32) int {
	value := a ^ b
	count := 0
	for value != 0 {
		count += int(value & 1)
		value >>= 1
	}
	return count
}
