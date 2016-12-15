package alert

import (
	"encoding/json"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/chenyoufu/jepl"
	"github.com/chenyoufu/yfstream/g"
	"github.com/wxjuyun/common/model"
	"github.com/wxjuyun/common/utils"
	"time"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func Alerter(in <-chan string) {

	l := make([]string, 0, 1024)
	interval := g.Config().Alert.Interval
	checker := time.NewTicker(time.Duration(interval) * time.Second)
	InitAlert()

	for {
		select {
		case <-checker.C:
			judge(l)
			l = l[:0]
		case v := <-in:
			l = append(l, v)
		}
	}
}

var globalRules = make(map[string]*model.Rule)
var globalStrategies = make(map[string]*model.Strategy)

func judge(messages []string) {

	for _, rule := range globalRules {

		stmt, e := jepl.ParseStatement(rule.SQL)
		checkErr(e)
		cond := stmt.(*jepl.SelectStatement).Condition

		fmt.Printf("timestamp: %d, doc count: %d\n", time.Now().Unix(), len(messages))
		fmt.Println(rule.SQL, rule.Note)
		for _, msg := range messages {
			doc, err := simplejson.NewJson([]byte(msg))
			checkErr(err)
			m := doc.MustMap()
			switch res := jepl.Eval(cond, m).(type) {
			case bool:
				if res == true {
					stmt.(*jepl.SelectStatement).EvalFunctionCalls(m)
				}
			default:
				fmt.Println("Select Where Condition parse error")
				fmt.Println(res)
			}
		}

		mps := stmt.(*jepl.SelectStatement).EvalMetric()

		metric := new(model.MetricValue)
		metric.RuleID = rule.RuleID
		metric.Value = mps[0].Metric
		metric.Timestamp = mps[0].TS

		fmt.Println(metric)

		strategy, ok := globalStrategies[rule.RuleID]
		fmt.Println(strategy)
		if !ok {
			continue
		}
		pk := utils.Md5(rule.RuleID)
		remain := 10
		now := time.Now().Unix()
		HistoryBigMap[pk[0:2]].PushFrontAndMaintain(pk, metric, remain, now)
		l, ok := HistoryBigMap[pk[0:2]].Get(pk)
		if !ok {
			continue
		}

		fn, err := ParseFuncFromString(strategy.Func, strategy.Op, strategy.Threshold)
		checkErr(err)

		isTriggered := fn.Compute(l)
		if isTriggered {
			event := &model.Event{
				Rule:        *rule,
				MetricValue: *metric,
				Strategy:    *strategy,
				Ets:         now,
			}
			sendEvent(event)
		}
	}
}

func sendEvent(event *model.Event) {

	bs, err := json.Marshal(event)
	checkErr(err)

	// send to redis
	redisKey := fmt.Sprintf("event:p%v", event.Strategy.Priority)
	rc := RedisConnPool.Get()
	defer rc.Close()
	rc.Do("LPUSH", redisKey, string(bs))
}
