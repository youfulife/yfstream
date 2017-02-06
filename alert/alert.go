package alert

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/chenyoufu/jepl"
	"github.com/chenyoufu/yfstream/g"
	"github.com/wxjuyun/common/model"
	"github.com/wxjuyun/common/utils"
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

		pointsM := jepl.EvalSQL(rule.SQL, messages)
		for k, mps := range pointsM {

			metric := new(model.MetricValue)
			metric.RuleID = rule.RuleID
			metric.Value = mps[0].Metric
			metric.Timestamp = mps[0].TS

			fmt.Println(k, metric)

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
