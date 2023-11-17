package utils

import "golang.org/x/exp/constraints"

func RotateLeft(v uint32, n int) uint32 {
	return (v << n) | (v >> (32 - n))
}

func RotateRight(v uint32, n int) uint32 {
	return (v >> n) | (v << (32 - n))
}

func GetBit[T constraints.Unsigned, U constraints.Integer](v T, n U) T {
	return (v >> n) & 1
}

func SetBit[T constraints.Unsigned, U constraints.Integer](a T, n U, v T) T {
	a = a & ^(1 << n)
	return a | (v << n)
}
