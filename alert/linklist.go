package alert

import (
	"container/list"
	"github.com/wxjuyun/common/model"
	"sync"
)

type SafeLinkedList struct {
	sync.RWMutex
	L *list.List
}

func (this *SafeLinkedList) Elem(offset int) *list.Element {
	curr := this.Front()
	for i := 0; i < offset; i++ {
		next := curr.Next()
		curr = next
	}
	return curr
}

func (this *SafeLinkedList) Values() []float64 {
	this.RLock()
	defer this.RUnlock()
	sz := this.L.Len()
	if sz == 0 {
		return []float64{}
	}

	ret := make([]float64, 0, sz)
	for e := this.L.Front(); e != nil; e = e.Next() {
		ret = append(ret, e.Value.(*model.MetricValue).Value)
	}
	return ret
}

func (this *SafeLinkedList) ToSlice() []*model.MetricValue {
	this.RLock()
	defer this.RUnlock()
	sz := this.L.Len()
	if sz == 0 {
		return []*model.MetricValue{}
	}

	ret := make([]*model.MetricValue, 0, sz)
	for e := this.L.Front(); e != nil; e = e.Next() {
		ret = append(ret, e.Value.(*model.MetricValue))
	}
	return ret
}

func (this *SafeLinkedList) PushFront(v interface{}) *list.Element {
	this.Lock()
	defer this.Unlock()
	return this.L.PushFront(v)
}

// @return needJudge 如果是false不需要做judge，因为新上来的数据不合法
func (this *SafeLinkedList) PushFrontAndMaintain(v *model.MetricValue, maxCount int) bool {
	this.Lock()
	defer this.Unlock()

	sz := this.L.Len()
	if sz > 0 {
		// 新push上来的数据有可能重复了，或者timestamp不对，这种数据要丢掉
		if v.Timestamp <= this.L.Front().Value.(*model.MetricValue).Timestamp || v.Timestamp <= 0 {
			return false
		}
	}

	this.L.PushFront(v)

	sz++
	if sz <= maxCount {
		return true
	}

	del := sz - maxCount
	for i := 0; i < del; i++ {
		this.L.Remove(this.L.Back())
	}

	return true
}

func (this *SafeLinkedList) Front() *list.Element {
	this.RLock()
	defer this.RUnlock()
	return this.L.Front()
}

func (this *SafeLinkedList) Len() int {
	this.RLock()
	defer this.RUnlock()
	return this.L.Len()
}
