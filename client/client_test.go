package client

import (
	"fmt"
	"testing"
)

import (
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
)

func Test_Main(t *testing.T) {
	//_, err := InitUser("aaaaaaa", "admin")
	//if err != nil {
	//	t.Log(err)
	//
	//	t.Fail()
	//}
	//_, err = GetUser("aaaaaaa", "admin")
	//if err != nil {
	//	t.Log(err)
	//
	//	t.Fail()
	//}
	//fmt.Println("hello")
	//var fileChain []int8
	////var hh []int8
	//
	//fileChain = append(fileChain, 2)

	//by, _ := json.Marshal(fileChain)
	//t.Log(by)
	//json.Unmarshal(by, &hh)

	//hash := userlib.RandomBytes(16)
	//t.Log(hh)
	//fileChain = append(fileChain, 1)
	//t.Log(uuid.FromBytes(hash))
	//a := userlib.RandomBytes(16)
	//b := userlib.RandomBytes(16)
	//t.Log(a)
	//t.Log(b)
	//
	//var s [][]byte
	//s = make([][]byte, 0)
	//s = append(s, a, b)
	//ret := bytes.Join(s, []byte(""))
	//t.Log(ret)
	var dic map[string]int8
	dic = make(map[string]int8)
	dic["2"] = 44
	dic["44wwq4"] = 4
	for s, i := range dic {
		fmt.Println(s, i)
	}
}

func Test_User(t *testing.T) {
	_, err := InitUser("aaaaaaa", "admin")
	if err != nil {
		t.Log(err)

		t.Fail()
	}
	user, err := GetUser("aaaaaaa", "admin")
	t.Log(user.Username)
	if err != nil {
		t.Log(err)

		t.Fail()
	}
	_, err = GetUser("a", "admin")
	if err == nil {
		t.Fail()
	} else {
		t.Log(err)
	}

	_, err = GetUser("aaaaaaa", "a")
	if err == nil {
		t.Fail()
	} else {
		t.Log(err)
	}
}
