package utils

func Xorshift32(value uint32) uint32 {
	if value == 0 {
		value = 0x6d2b79f5
	}
	value ^= value << 13
	value ^= value >> 17
	value ^= value << 5
	return value
}

func RotateLeft32(value uint32, shift uint) uint32 {
	shift %= 32
	if shift == 0 {
		return value
	}
	return (value << shift) | (value >> (32 - shift))
}
