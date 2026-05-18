package padding

import "fmt"

const BlockSize = 4

// AddPadding completa o texto ate um multiplo de 4 bytes.
// O valor escrito em cada byte indica quantos bytes foram adicionados.
func AddPadding(data []byte) []byte {
	padding := BlockSize - (len(data) % BlockSize)
	if padding == 0 {
		padding = BlockSize
	}

	out := make([]byte, 0, len(data)+padding)
	out = append(out, data...)
	for i := 0; i < padding; i++ {
		out = append(out, byte(padding))
	}
	return out
}

// RemovePadding valida e remove o padding adicionado antes da cifragem.
func RemovePadding(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%BlockSize != 0 {
		return nil, fmt.Errorf("padding invalido")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > BlockSize || padding > len(data) {
		return nil, fmt.Errorf("padding invalido")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, fmt.Errorf("padding invalido")
		}
	}

	return data[:len(data)-padding], nil
}
