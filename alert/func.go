package alert

import (
	"fmt"
	"github.com/wxjuyun/common/model"
	"math"
	"strconv"
	"strings"
)

type Function interface {
	Compute(L *SafeLinkedList) (isTriggered bool)
}

type AllFunction struct {
	Function
	Limit      int
	Operator   string
	RightValue float64
}

func (this AllFunction) Compute(L *SafeLinkedList) (isTriggered bool) {
	if L.Len() < this.Limit {
		return false
	}

	isTriggered = true
	for i := 0; i < this.Limit; i++ {
		isTriggered = checkIsTriggered(L.Elem(i).Value.(*model.MetricValue).Value, this.Operator, this.RightValue)
		if !isTriggered {
			break
		}
	}
	return
}

// @str: e.g. all(#3) sum(#3) avg(#10) diff(#10)
func ParseFuncFromString(str string, operator string, rightValue float64) (fn Function, err error) {
	idx := strings.Index(str, "#")
	limit, err := strconv.ParseInt(str[idx+1:len(str)-1], 10, 64)
	if err != nil {
		return nil, err
	}

	switch str[:idx-1] {
	case "all":
		fn = &AllFunction{Limit: int(limit), Operator: operator, RightValue: rightValue}
	default:
		err = fmt.Errorf("not_supported_method")
	}

	return
}

func checkIsTriggered(leftValue float64, operator string, rightValue float64) (isTriggered bool) {
	switch operator {
	case "=", "==":
		isTriggered = math.Abs(leftValue-rightValue) < 0.0001
	case "!=":
		isTriggered = math.Abs(leftValue-rightValue) > 0.0001
	case "<":
		isTriggered = leftValue < rightValue
	case "<=":
		isTriggered = leftValue <= rightValue
	case ">":
		isTriggered = leftValue > rightValue
	case ">=":
		isTriggered = leftValue >= rightValue
	}

	return
}
