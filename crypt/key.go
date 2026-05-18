package crypt

import "github.com/rafinhacuri/crypt/utils"

func MasterKey(keyText string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(keyText); i++ {
		hash ^= uint32(keyText[i])
		hash *= 16777619
		hash = utils.RotateLeft32(hash, 5) ^ uint32(i+1)*0x9e3779b9
	}
	if hash == 0 {
		return 0xa5a5f00d
	}
	return hash
}

func DeriveSubkeys(keyText string) [Rounds]uint32 {
	var subkeys [Rounds]uint32
	state := MasterKey(keyText)

	for i := range Rounds {
		state ^= uint32(i+1) * 0x9e3779b9
		state = utils.Xorshift32(state)
		state += utils.RotateLeft32(MasterKey(keyText), uint(i+3))
		subkeys[i] = state ^ uint32(i+1)*0x7f4a7c15
	}

	return subkeys
}
