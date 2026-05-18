package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/rafinhacuri/crypt/crypt"
	"github.com/rafinhacuri/crypt/filecrypt"
)

func main() {
	mode := flag.String("mode", "", "operacao: encrypt ou decrypt")
	input := flag.String("in", "", "arquivo de entrada")
	output := flag.String("out", "", "arquivo de saida")
	key := flag.String("key", "", "chave textual usada para gerar a chave de 32 bits")
	flag.Parse()

	if err := run(*mode, *input, *output, *key); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func run(mode, input, output, key string) error {
	if mode == "" || key == "" {
		return fmt.Errorf("uso: go run . -mode encrypt|decrypt -in entrada -out saida -key chave")
	}
	if mode != "trace" && (input == "" || output == "") {
		return fmt.Errorf("uso: go run . -mode encrypt|decrypt -in entrada -out saida -key chave")
	}

	switch mode {
	case "encrypt", "enc", "encriptar":
		return filecrypt.EncryptFile(input, output, key)
	case "decrypt", "dec", "decriptar":
		return filecrypt.DecryptFile(input, output, key)
	case "trace":
		return printTrace(input, key)
	default:
		return fmt.Errorf("modo invalido %q", mode)
	}
}

func printTrace(blockText, key string) error {
	block, err := parseBlock(blockText)
	if err != nil {
		return err
	}

	cipher := crypt.NewCipher(key)
	fmt.Printf("Bloco inicial: 0x%08X\n", block)
	for _, step := range cipher.TraceEncryptBlock(block) {
		fmt.Printf(
			"Rodada %d | Subchave 0x%08X | XOR 0x%08X | Mistura 0x%08X | Substituicao 0x%08X | Permutacao 0x%08X\n",
			step.Round,
			step.Subkey,
			step.AfterXOR,
			step.AfterKeyMix,
			step.AfterSubstitution,
			step.AfterPermutation,
		)
	}
	fmt.Printf("Texto cifrado: 0x%08X\n", cipher.EncryptBlock(block))
	return nil
}

func parseBlock(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("bloco invalido: use um valor de 32 bits, por exemplo 0x494E4E21")
	}
	return uint32(parsed), nil
}
