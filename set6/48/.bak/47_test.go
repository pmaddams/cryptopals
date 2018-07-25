package main

import (
	"math/big"
	"reflect"
	"testing"
)

func TestValues(t *testing.T) {
	cases := []struct {
		ch   <-chan *big.Int
		want []*big.Int
	}{
		{
			Values(zero, one),
			[]*big.Int{zero, one},
		},
		{
			Values(zero, two),
			[]*big.Int{zero, one, two},
		},
		{
			Values(zero, three),
			[]*big.Int{zero, one, two, three},
		},
	}
	for _, c := range cases {
		got := func(ch <-chan *big.Int) []*big.Int {
			var res []*big.Int
			for z := range ch {
				res = append(res, z)
			}
			return res
		}(c.ch)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
