package cook

import (
	"github.com/bitly/go-simplejson"
	"github.com/chenyoufu/yfstream/grok"
	"github.com/chenyoufu/yfstream/ipsearch"
	"github.com/mssola/user_agent"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//Cooker ...
type Cooker struct {
	ipsearch *ipsearch.IPSearch
	grok     *grok.Grok
}

var ipRegionFile = "regionIp.dat"
var patternsDir = "grok_patterns"

//InitCooker return a Cooker
func InitCooker() Cooker {
	grokConfig := &grok.Config{
		NamedCapturesOnly: true,
		RemoveEmptyValues: false,
		PatternsDir:       patternsDir,
	}
	g, _ := grok.New(grokConfig)
	p, _ := ipsearch.New(ipRegionFile)

	return Cooker{p, g}
}

//Cook return a string be cooked and error
func (c *Cooker) Cook(msg string) ([]byte, error) {
	ts0 := time.Now()
	js, err := simplejson.NewJson([]byte(msg))
	if err != nil {
		return nil, err
	}
	js.Set("cook_ts0", ts0.UnixNano()/1000)
	if _, e := js.Get("@timestamp").String(); e != nil {
		// RFC3339     = "2006-01-02T15:04:05Z07:00"
		js.Set("@timestamp", ts0.Format(time.RFC3339))
	}

	docType, err := js.Get("type").String()
	if err != nil {
		return nil, err
	}

	if ip, e := js.Get(docType).Get("src_ip").String(); e == nil {
		js.SetPath([]string{docType, "src_ip"}, c.handleIP(ip))
	} else if num, e := js.Get(docType).Get("src_ip").Int(); e == nil {
		js.SetPath([]string{docType, "src_ip"}, c.handleIP(num))
	}

	if ip, e := js.Get(docType).Get("dst_ip").String(); e == nil {
		js.SetPath([]string{docType, "dst_ip"}, c.handleIP(ip))
	} else if num, e := js.Get(docType).Get("dst_ip").Int(); e == nil {
		js.SetPath([]string{docType, "dst_ip"}, c.handleIP(num))
	}

	if ua, e := js.Get(docType).Get("user_agent").String(); e == nil {
		js.SetPath([]string{docType, "user_agent"}, c.handleUA(ua))
	}

	ts1 := time.Now()
	js.Set("cook_ts1", ts1.UnixNano()/1000)
	js.Set("cook_latency_us", (ts1.UnixNano()-ts0.UnixNano())/1000)
	bs, err := js.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return bs, nil
}

func (c *Cooker) handleUA(s string) map[string]interface{} {
	ua := user_agent.New(s)
	m := make(map[string]interface{})
	m["raw"] = s
	if len(s) > 0 {
		m["browser"], m["browser_version"] = ua.Browser()
		m["os"] = ua.OS()
		m["platform"] = ua.Platform()
		m["engine"], m["engine_version"] = ua.Engine()
		m["bot"] = ua.Bot()
	}
	return m
}

func (c *Cooker) handleIP(ip interface{}) map[string]interface{} {
	ipInfo := c.ipsearch.Get(ip)
	m := make(map[string]interface{})
	m["raw"] = ip
	m["region"] = ""
	m["isp"] = ""
	m["latitude"] = ""
	m["longtitude"] = ""

	var intIP uint32
	var ips string
	switch t := ip.(type) {
	case string:
		ips = ip.(string)
		if len(ips) == 0 {
			intIP = 0
		} else {
			intIP = ipsearch.IpToLong(ip.(string))
		}
	case int:
		intIP = uint32(ip.(int))
	case uint32:
		intIP = ip.(uint32)
	default:
		log.Fatalf("ip type not support %s", t)
	}
	m["decimal"] = intIP
	m["dotted"] = ipsearch.LongToIp(intIP)

	if len(ipInfo) > 0 {
		sl := strings.Split(ipInfo, "|")
		if len(sl) > 10 && sl[5] != "qqzeng-ip" {
			m["region"] = sl[3]
			m["isp"] = sl[5]
			m["latitude"] = sl[9]
			m["longtitude"] = sl[10]
		}
	}
	return m
}

func (c *Cooker) handlePerfData(s string) map[string]interface{} {
	m := make(map[string]interface{})
	m["raw"] = s
	re, _ := regexp.Compile(`(^|\s).*?=\d+\.*\d*`)
	fileds := re.FindAllString(s, -1)
	for _, v := range fileds {
		sp := strings.Split(v, "=")
		f, _ := strconv.ParseFloat(sp[1], 32)
		f = ((float64)((int)((f + 0.005) * 100))) / 100
		k := strings.TrimSpace(sp[0])
		m[k] = f
	}
	return m
}
