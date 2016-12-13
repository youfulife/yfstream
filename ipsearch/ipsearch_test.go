package ipsearch

import (
	"fmt"
	"testing"
)

/**
 * @author xiao.luo
 * @description This is the unit test for IpSearch
 */

func TestLoad(t *testing.T) {
	fmt.Println("Test Load IP Dat ...")
	p, err := New("./regionIp.dat")
	if len(p.data) <= 0 || err != nil {
		t.Fatal("the IP Dat did not loaded successfully!")
	}
}

func TestGet(t *testing.T) {
	var tests = []struct {
		input interface{}
		want  string
	}{
		{"", ``},
		{0, ``},
		{"210.51.200.123", `亚洲|中国|湖北| |潜江|联通|429005|China|CN|112.896866|30.421215`},
		{3526609019, `亚洲|中国|湖北| |潜江|联通|429005|China|CN|112.896866|30.421215`},
	}
	p, _ := New("./regionIp.dat")
	for _, test := range tests {
		if got := p.Get(test.input); got != test.want {
			t.Errorf("Get(%q) = %v, but we want %v", test.input, got, test.want)
		}
	}
}

func TestGetISP(t *testing.T) {
	p, _ := New("./regionIp.dat")
	ip := "210.51.200.123"
	isp := p.GetISP(ip)
	fmt.Println(isp)
	if isp != `联通` {
		t.Fatal("the IP convert by ipSearch component is not correct!")
	}
}

func TestGetRegionCode(t *testing.T) {
	p, _ := New("./regionIp.dat")
	ip := "210.51.200.123"
	rc := p.GetRegionCode(ip)
	fmt.Println(rc)
	if rc != `429005` {
		t.Fatal("the IP convert by ipSearch component is not correct!")
	}
}
