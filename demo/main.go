package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"os"
)

type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

func (circuit *CubicCircuit) Define(api frontend.API) error {
	xCubic := api.Mul(circuit.X, circuit.X, circuit.X)
	doubleX := api.Mul(2, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(xCubic, doubleX, 5))
	return nil
}

func main() {
	//实例化CubicCircuit
	c := CubicCircuit{
		X: 3,
		Y: 38,
	}
	// compile a circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	if err != nil {
		panic(err)
	}
	//
	fKzgSrs, err := os.Open("../data/kzg_srs_1008000_bn254_TINY_TEST_7")
	if err != nil {
		panic(err)
	}
	defer fKzgSrs.Close()
	kzgSrs := kzg.NewSRS(ecc.BN254)
	_, err = kzgSrs.ReadFrom(fKzgSrs)
	if err != nil {
		panic(err)
	}
	_, _, err = plonk.Setup(ccs, kzgSrs)
	if err != nil {
		panic(err)
	}
	fmt.Println("end now ...")

}
