package compiled

import (
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"math/big"
	"os"
	"sort"
)

type LazyR1CS []LazyInputs

func (l *LazyR1CS) GetConstraintsAll() int {
	sum := 0
	for _, v := range *l {
		sum += v.GetConstraintsNum()
	}
	return sum
}

type LazyMimcEncInputs struct {
	S0, HH, V LinearExpression
	Loc       int
}

type CoeffTable interface {
	GetCoeffID(v *big.Int) int
	CoeffID(v *big.Int) int
	GetCoeffsById(id int) *big.Int
}

type LazyInputs interface {
	GetConstraintsNum() int
	GetLoc() int
	FetchLazy(j int, r1cs *R1CS, coefs CoeffTable) R1C
	GetType(coefs CoeffTable) string
	SetConsStaticR1CMapIfNotExists(r1cs *R1CS, coefs CoeffTable) error
	GetInitialIndex() int
	GetShift(r1cs *R1CS, table CoeffTable) int
	IsInput(j int, loc uint8) bool
}

type LazyIndexedInputs struct {
	Index     int
	LazyIndex int
}

func (le *LazyMimcEncInputs) GetConstraintsNum() int {
	return 273
}

func (le *LazyMimcEncInputs) GetInitialIndex() int {
	return le.V[0].WireID() - le.GetConstraintsNum()
}

func (le *LazyMimcEncInputs) IsInput(j int, loc uint8) bool {
	if (j == 0) && loc == 1 {
		return true
	}
	// s0, s1
	if (j == 0) && loc == 2 {
		return true
	}
	// s0, s1
	if (j == 2) && loc == 2 {
		return true
	}

	return false
}

func getNewAddRes(S0, HH frontend.Variable, Coefs CoeffTable) LinearExpression {
	// modify line 0 and 2
	// update internal variable idx with shift V.idx - 272
	params := bn254.GetConstants()
	//shift := V.(.LinearExpression)[0].WireID() - V0.(.LinearExpression)[0].WireID()
	//res := r1c

	// start of wid
	x := S0.(LinearExpression)
	zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
	addRes := make(LinearExpression, 0)
	{
		vars := make([]LinearExpression, 0, 3)
		vars = append(vars, x)

		HHL := HH.(LinearExpression)
		vars = append(vars, HHL)

		one := LinearExpression{Pack(0, CoeffIdOne, schema.Public)}
		cID := Coefs.GetCoeffID(&params[0])
		if cID == -1 {
			os.Exit(-1)
		}
		one[0].SetCoeffID(cID) //TODO
		vars = append(vars, one)

		for _, v := range vars {
			if v.Equal(zero) {
				continue
			}
			addRes = append(addRes, v...)
		}
		if !sort.IsSorted(addRes) {
			sort.Sort(addRes)
		}
		mod := ecc.BN254.Info().Fr.Modulus()
		c := new(big.Int)
		for i := 1; i < len(addRes); i++ {
			pcID, pvID, pVis := addRes[i-1].Unpack()
			rcID, rvID, rVis := addRes[i].Unpack()
			if pVis == rVis && pvID == rvID {
				// we have redundancy
				c.Add(Coefs.GetCoeffsById(pcID), Coefs.GetCoeffsById(rcID))
				c.Mod(c, mod)
				ccID := Coefs.GetCoeffID(c)
				addRes[i-1].SetCoeffID(ccID)
				addRes = append(addRes[:i], addRes[i+1:]...)
				i--
			}
		}
	}

	return addRes
}

func fetchMimcLazy(S0, HH frontend.Variable, staticR1c []R1C, j int, Coefs CoeffTable) R1C {
	if j == 0 {
		addRes := getNewAddRes(S0, HH, Coefs)
		resL := addRes.Clone()
		resR := addRes.Clone()
		resO := staticR1c[0].O.Clone()
		return R1C{
			L: resL,
			R: resR,
			O: resO,
		}
	}

	if j == 2 {
		addRes := getNewAddRes(S0, HH, Coefs)
		resL := staticR1c[2].L.Clone()
		resR := addRes.Clone()
		resO := staticR1c[2].O.Clone()
		return R1C{
			L: resL,
			R: resR,
			O: resO,
		}

	}

	resL := staticR1c[j].L.Clone()
	resR := staticR1c[j].R.Clone()
	resO := staticR1c[j].O.Clone()

	return R1C{
		L: resL,
		R: resR,
		O: resO,
	}
}

func (le *LazyMimcEncInputs) FetchLazy(j int, r1cs *R1CS, coefs CoeffTable) R1C {
	return fetchMimcLazy(le.S0, le.HH, r1cs.LazyConsStaticR1CMap[le.GetType(coefs)], j, coefs)
}

func (le *LazyMimcEncInputs) GetLoc() int {
	return le.Loc
}

func (le *LazyMimcEncInputs) GetType(coefs CoeffTable) string {
	return "mimc-enc"
}

// StaticEncrypt static expanding constraints
// should use HH=0 to init
func staticEncrypt(S0, HH, V frontend.Variable, Coefs CoeffTable) []R1C {
	params := bn254.GetConstants()
	res := make([]R1C, 0)

	// start of wid
	wid := V.(LinearExpression)[0].WireID() - 272
	x := S0.(LinearExpression)
	for i := 0; i < len(params); i++ {
		// x = h.api.Add(x, HH, h.params[i]).(LinearExpression)
		zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
		addRes := make(LinearExpression, 0)
		{
			vars := make([]LinearExpression, 0, 3)
			vars = append(vars, x)

			HHL := HH.(LinearExpression)
			vars = append(vars, HHL)

			one := LinearExpression{Pack(0, CoeffIdOne, schema.Public)}
			cID := Coefs.GetCoeffID(&params[i])
			if cID == -1 {
				os.Exit(-1)
			}
			one[0].SetCoeffID(cID) //TODO
			vars = append(vars, one)

			for _, v := range vars {
				if v.Equal(zero) {
					continue
				}
				addRes = append(addRes, v...)
			}
			if !sort.IsSorted(addRes) {
				sort.Sort(addRes)
			}
			// // TODO Reduce just check 0?
			mod := ecc.BN254.Info().Fr.Modulus()
			c := new(big.Int)
			for i := 1; i < len(addRes); i++ {
				pcID, pvID, pVis := addRes[i-1].Unpack()
				ccID, cvID, cVis := addRes[i].Unpack()
				if pVis == cVis && pvID == cvID {
					// we have redundancy
					c.Add(Coefs.GetCoeffsById(pcID), Coefs.GetCoeffsById(ccID))
					c.Mod(c, mod)
					ccID := Coefs.GetCoeffID(c)
					addRes[i-1].SetCoeffID(ccID)
					addRes = append(addRes[:i], addRes[i+1:]...)
					i--
				}
			}
		}

		// x = pow5(h.api, addRes)
		// // r = h.api.Mul(addRes, addRes)
		// // r = h.api.Mul(r, r)
		// // x = h.api.Mul(r, addRes)
		r := V.(LinearExpression).Clone()
		r[0].SetWireID(wid)
		res = append(res, R1C{
			L: addRes,
			R: addRes,
			O: r})
		r2 := r.Clone()
		r2[0].SetWireID(wid + 1)
		res = append(res, R1C{
			L: r,
			R: r,
			O: r2})
		r3 := r2.Clone()
		r3[0].SetWireID(wid + 2)
		res = append(res, R1C{
			L: r2,
			R: addRes,
			O: r3})

		wid += 3
		x = r3.Clone() //TODO
	}

	return res
}

func (le *LazyMimcEncInputs) SetConsStaticR1CMapIfNotExists(r1cs *R1CS, table CoeffTable) error {
	if _, ok := r1cs.LazyConsStaticR1CMap[le.GetType(table)]; !ok {
		r1cs.LazyConsOriginInputMap[le.GetType(table)] = le
		r1cs.LazyConsStaticR1CMap[le.GetType(table)] = staticEncrypt(le.S0, le.HH, le.V, table)
	}
	return nil
}

func GetShift(V, V0 frontend.Variable) int {
	vWire := V.(LinearExpression)[0].WireID()
	v0Wire := V0.(LinearExpression)[0].WireID()
	shift := vWire - v0Wire

	return shift
}

func (le *LazyMimcEncInputs) GetShift(r1cs *R1CS, table CoeffTable) int {
	return GetShift(le.V, r1cs.LazyConsOriginInputMap[le.GetType(table)].(*LazyMimcEncInputs).V)
}
