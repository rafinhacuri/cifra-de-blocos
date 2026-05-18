package utils

func BytesToUint32(data []byte) uint32 {
	return uint32(data[0])<<24 |
		uint32(data[1])<<16 |
		uint32(data[2])<<8 |
		uint32(data[3])
}

func Uint32ToBytes(value uint32) []byte {
	return []byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	}
}
