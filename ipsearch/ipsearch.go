package ipsearch

import (
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
)

/**
 * @author xiao.luo
 * @description This is the go version for IPSearch
 */

type ipIndex struct {
	startip, endip           uint32
	localOffset, localLength uint32
}

type prefixIndex struct {
	startIndex, endIndex uint32
}

// IPSearch structure used for search region
type IPSearch struct {
	data               []byte
	prefixMap          map[uint32]prefixIndex
	firstStartIPOffset uint32
	prefixStartOffset  uint32
	prefixEndOffset    uint32
	prefixCount        uint32
}

//New IPSearch
func New(regionIPFile string) (*IPSearch, error) {

	ips, err := loadIPDat(regionIPFile)
	if err != nil {
		log.Fatal("the IP Dat loaded failed!")
		return ips, err
	}
	return ips, nil
}

func loadIPDat(regionIPFile string) (*IPSearch, error) {

	p := IPSearch{}
	//加载ip地址库信息
	data, err := ioutil.ReadFile(regionIPFile)
	if err != nil {
		log.Fatal(err)
	}
	p.data = data
	p.prefixMap = make(map[uint32]prefixIndex)

	p.firstStartIPOffset = bytesToLong(data[0], data[1], data[2], data[3])
	p.prefixStartOffset = bytesToLong(data[8], data[9], data[10], data[11])
	p.prefixEndOffset = bytesToLong(data[12], data[13], data[14], data[15])
	p.prefixCount = (p.prefixEndOffset-p.prefixStartOffset)/9 + 1 // 前缀区块每组

	// 初始化前缀对应索引区区间
	indexBuffer := p.data[p.prefixStartOffset:(p.prefixEndOffset + 9)]
	for k := uint32(0); k < p.prefixCount; k++ {
		i := k * 9
		prefix := uint32(indexBuffer[i] & 0xFF)

		pf := prefixIndex{}
		pf.startIndex = bytesToLong(indexBuffer[i+1], indexBuffer[i+2], indexBuffer[i+3], indexBuffer[i+4])
		pf.endIndex = bytesToLong(indexBuffer[i+5], indexBuffer[i+6], indexBuffer[i+7], indexBuffer[i+8])
		p.prefixMap[prefix] = pf

	}
	return &p, nil
}

// Get to an ip info string
func (p *IPSearch) Get(ip interface{}) string {
	var intIP uint32

	switch t := ip.(type) {
	case string:
		ips := ip.(string)
		if len(ips) == 0 {
			intIP = 0
			break
		}
		intIP = IpToLong(ip.(string))
	case int:
		intIP = uint32(ip.(int))
	case uint32:
		intIP = ip.(uint32)
	default:
		log.Fatalf("ip type not support %s", t)
		return ""
	}

	if intIP == 0 {
		return ""
	}

	prefix := intIP >> 24
	var high uint32
	var low uint32

	if _, ok := p.prefixMap[prefix]; ok {
		low = p.prefixMap[prefix].startIndex
		high = p.prefixMap[prefix].endIndex
	} else {
		return ""
	}

	var myIndex uint32
	if low == high {
		myIndex = low
	} else {
		myIndex = p.binarySearch(low, high, intIP)
	}

	ipindex := &ipIndex{}
	ipindex.getIndex(myIndex, p)

	if ipindex.startip <= intIP && ipindex.endip >= intIP {
		return ipindex.getLocal(p)
	}
	return ""
}

// GetRegionCode return the ip region code string
func (p *IPSearch) GetRegionCode(ip string) string {
	ipInfo := p.Get(ip)
	if len(ipInfo) > 0 {
		sl := strings.Split(ipInfo, "|")
		return sl[6]
	}
	return ""
}

// GetISP return the ip region code string
func (p *IPSearch) GetISP(ip string) string {
	ipInfo := p.Get(ip)
	if len(ipInfo) > 0 {
		sl := strings.Split(ipInfo, "|")
		return sl[5]
	}
	return ""
}

// 二分逼近算法
func (p *IPSearch) binarySearch(low uint32, high uint32, k uint32) uint32 {
	var M uint32
	for low <= high {
		mid := (low + high) / 2

		endipNum := p.getEndIP(mid)
		if endipNum >= k {
			M = mid
			if mid == 0 {
				break // 防止溢出
			}
			high = mid - 1
		} else {
			low = mid + 1
		}
	}
	return M
}

// 只获取结束ip的数值
// 索引区第left个索引
// 返回结束ip的数值
func (p *IPSearch) getEndIP(left uint32) uint32 {
	leftOffset := p.firstStartIPOffset + left*12
	return bytesToLong(p.data[4+leftOffset], p.data[5+leftOffset], p.data[6+leftOffset], p.data[7+leftOffset])

}

func (p *ipIndex) getIndex(left uint32, ips *IPSearch) {
	leftOffset := ips.firstStartIPOffset + left*12
	p.startip = bytesToLong(ips.data[leftOffset], ips.data[1+leftOffset], ips.data[2+leftOffset], ips.data[3+leftOffset])
	p.endip = bytesToLong(ips.data[4+leftOffset], ips.data[5+leftOffset], ips.data[6+leftOffset], ips.data[7+leftOffset])
	p.localOffset = bytesToLong3(ips.data[8+leftOffset], ips.data[9+leftOffset], ips.data[10+leftOffset])
	p.localLength = uint32(ips.data[11+leftOffset])
}

// / 返回地址信息
// / 地址信息的流位置
// / 地址信息的流长度
func (p *ipIndex) getLocal(ips *IPSearch) string {
	bytes := ips.data[p.localOffset : p.localOffset+p.localLength]
	return string(bytes)

}

func IpToLong(ip string) uint32 {
	quads := strings.Split(ip, ".")
	if len(quads) != 4 {
		return 0
	}
	var result uint32
	a, _ := strconv.Atoi(quads[3])
	result += uint32(a)
	b, _ := strconv.Atoi(quads[2])
	result += uint32(b) << 8
	c, _ := strconv.Atoi(quads[1])
	result += uint32(c) << 16
	d, _ := strconv.Atoi(quads[0])
	result += uint32(d) << 24
	return result
}

//LongToIp Convert uint to net.IP
func LongToIp(ipnr uint32) string {
	var bytes [4]byte
	bytes[0] = byte(ipnr & 0xFF)
	bytes[1] = byte((ipnr >> 8) & 0xFF)
	bytes[2] = byte((ipnr >> 16) & 0xFF)
	bytes[3] = byte((ipnr >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]).String()
}

//字节转整形
func bytesToLong(a, b, c, d byte) uint32 {
	a1 := uint32(a)
	b1 := uint32(b)
	c1 := uint32(c)
	d1 := uint32(d)
	return (a1 & 0xFF) | ((b1 << 8) & 0xFF00) | ((c1 << 16) & 0xFF0000) | ((d1 << 24) & 0xFF000000)
}

func bytesToLong3(a, b, c byte) uint32 {
	a1 := uint32(a)
	b1 := uint32(b)
	c1 := uint32(c)
	return (a1 & 0xFF) | ((b1 << 8) & 0xFF00) | ((c1 << 16) & 0xFF0000)

}
