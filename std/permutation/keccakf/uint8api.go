package keccakf

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Uint8api performs binary operations on Xuint8 variables.
type Uint8api struct {
	api frontend.API
}

func NewUint8API(api frontend.API) *Uint8api {
	return &Uint8api{
		api: api,
	}
}

// Xuint8 represents 8-bit byte. We use this type to ensure that
// we work over constrained bits.
type Xuint8 [8]frontend.Variable

func ConstUint8(a uint8) Xuint8 {
	var res Xuint8
	for i := 0; i < 8; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *Uint8api) AsUint8FromBytes(in ...frontend.Variable) Xuint8 {
	return w.AsUint8(bits.FromBinary(w.api, in))
}

func (w *Uint8api) AsUint8(in frontend.Variable) Xuint8 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(8))
	var res Xuint8
	copy(res[:], bits)
	return res
}

func (w *Uint8api) FromUint8(in Xuint8) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *Uint8api) And(in ...Xuint8) Xuint8 {
	var res Xuint8
	for i := range res {
		res[i] = 1
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.And(res[i], v[i])
		}
	}
	return res
}

func (w *Uint8api) Or(in ...Xuint8) Xuint8 {
	var res Xuint8
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Or(res[i], v[i])
		}
	}
	return res
}

func (w *Uint8api) assertEq(a, b Xuint8) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}

func (w *Uint8api) DecodeToXuint64(b []Xuint8) Xuint64 {
	var bits []frontend.Variable
	for i := 0; i < 8; i++ {
		bits = append(bits, b[i][:]...)
	}

	var res Xuint64
	copy(res[:], bits[:])
	return res
}

func (w *Uint8api) EncodeToXuint8(b []Xuint8, x Xuint64) []Xuint8 {
	var res [8]Xuint8
	copy(res[0][:], x[0:8])
	copy(res[1][:], x[8:16])
	copy(res[2][:], x[16:24])
	copy(res[3][:], x[24:32])
	copy(res[4][:], x[32:40])
	copy(res[5][:], x[40:48])
	copy(res[6][:], x[48:56])
	copy(res[7][:], x[56:64])
	return append(b, res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7])
}
