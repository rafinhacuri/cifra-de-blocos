package filecrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCBCRoundTrip(t *testing.T) {
	// Testa o fluxo em memoria: cifra em CBC e decifra para recuperar os dados.
	data := []byte("contrato 123 - sinistro aprovado")
	key := "chave-inicial"
	iv := uint32(0x01020304)

	encrypted := EncryptCBC(data, key, iv)
	decrypted, err := DecryptCBC(encrypted, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("got %q, want %q", decrypted, data)
	}
}

func TestCBCRejectsWrongKey(t *testing.T) {
	// A etiqueta de verificacao deve rejeitar a decriptacao com chave incorreta.
	data := []byte("dados pessoais")
	encrypted := EncryptCBC(data, "chave-correta", 0x10203040)

	if _, err := DecryptCBC(encrypted, "chave-errada", 0x10203040); err == nil {
		t.Fatal("expected wrong key to be rejected")
	}
}

func TestFileRoundTrip(t *testing.T) {
	// Testa o caso completo com arquivos reais em uma pasta temporaria.
	dir := t.TempDir()
	input := filepath.Join(dir, "entrada.txt")
	encrypted := filepath.Join(dir, "saida.is32")
	decrypted := filepath.Join(dir, "saida.txt")
	data := []byte("arquivo de teste para cifra de blocos")

	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(input, encrypted, "senha"); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(encrypted, decrypted, "senha"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q, want %q", got, data)
	}
}
