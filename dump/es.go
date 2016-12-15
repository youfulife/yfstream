package dump

import (
	"bytes"
	"fmt"
	"github.com/buger/jsonparser"
	"github.com/chenyoufu/yfstream/g"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

//Dump2ES fetch a string from in channel,then encode to es bulk and post it non block
func Dump2ES(in <-chan string) {
	var buffer bytes.Buffer
	var bulkCounter uint64
	dumper := time.NewTicker(1 * time.Second) // 1s

	for {
		select {
		case <-dumper.C:
			// log.Printf("body len: %d, bulk count %d\n", buffer.Len(), bulkCounter)
			if buffer.Len() == 0 {
				break
			}
			go dump2es(buffer.String())
			buffer.Reset()
		case v := <-in:
			bulk, err := encode2EsBulk(v)
			if err != nil {
				break
			}
			buffer.WriteString(string(bulk))
			bulkCounter++
		}
	}
}

//encode2EsBulk return esbulk formatting string
func encode2EsBulk(msg string) ([]byte, error) {
	prefix := g.Config().Dump.ES.IndexPrefix
	suffix := g.Config().Dump.ES.IndexSuffix
	docType, err := jsonparser.GetString([]byte(msg), "type")
	if err != nil {
		return nil, err
	}
	guid, err := jsonparser.GetString([]byte(msg), "guid")
	if err != nil {
		return nil, err
	}
	topic, err := jsonparser.GetString([]byte(msg), "kafka", "topic")
	if err != nil {
		return nil, err
	}
	index := fmt.Sprintf("%s-%s-%s-%s", prefix, topic, guid, time.Now().Format(suffix))

	action := fmt.Sprintf(`{create: {"_index": %s, "_type": %s}}`, index, docType)
	bulk := fmt.Sprintf("%s\n%s\n", action, msg)
	return []byte(bulk), nil
}

// Create a new transport and HTTP client
var tr = &http.Transport{}
var client = &http.Client{Transport: tr}

//dump2es post the es bulk format string via http interface
func dump2es(body string) {
	bulkURL := g.Config().Dump.ES.BulkURL
	resp, err := client.Post(bulkURL, "text", strings.NewReader(body))
	if err != nil {
		log.Printf("Can't post body: %s, resp: %#v, error: %s", body, resp, err.Error())
		return
	}

	io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()
	return
}
