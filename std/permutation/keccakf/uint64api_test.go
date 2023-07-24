package keccakf

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type lrotCirc struct {
	In    frontend.Variable
	Shift int
	Out   frontend.Variable
}

type andCirc struct {
	In1 frontend.Variable
	In2 frontend.Variable
	Out frontend.Variable
}

func (c *lrotCirc) Define(api frontend.API) error {
	uapi := NewUint64API(api)
	in := uapi.AsUint64(c.In)
	out := uapi.AsUint64(c.Out)
	res := uapi.Lrot(in, c.Shift)
	uapi.assertEq(out, res)
	return nil
}

func (c *andCirc) Define(api frontend.API) error {
	uapi := NewUint64API(api)
	in1 := uapi.AsUint64(c.In1)
	in2 := uapi.AsUint64(c.In2)
	out := uapi.AsUint64(c.Out)
	res := uapi.And(in1, in2)
	uapi.assertEq(out, res)
	return nil
}

func TestLeftRotation(t *testing.T) {
	assert := test.NewAssert(t)
	// err := test.IsSolved(&lrotCirc{Shift: 2}, &lrotCirc{In: 6, Shift: 2, Out: 24}, ecc.BN254.ScalarField())
	// assert.NoError(err)
	assert.ProverSucceeded(&lrotCirc{Shift: 2}, &lrotCirc{In: 6, Shift: 2, Out: 24})
}

func TestAnd(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&andCirc{In1: 2, In2: 6, Out: 2}, &andCirc{In1: 2, In2: 6, Out: 2})
}
