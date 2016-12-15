package pull

import (
	"github.com/Shopify/sarama"
	"github.com/bitly/go-simplejson"
	"github.com/chenyoufu/yfstream/g"
	"log"
)

//SemiCooKafkaMsg merge the kafka metadata to message
func SemiCooKafkaMsg(msg *sarama.ConsumerMessage) ([]byte, error) {
	js, err := simplejson.NewJson(msg.Value)
	if err != nil {
		return nil, err
	}

	js.SetPath([]string{"kafka", "topic"}, msg.Topic)
	js.SetPath([]string{"kafka", "partition"}, msg.Partition)
	js.SetPath([]string{"kafka", "offset"}, msg.Offset)
	bs, err := js.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return bs, nil
}

//InitKafkaPCS returns the kafka consumer partition channels
func InitKafkaPCS() (pcs []sarama.PartitionConsumer) {

	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Net.MaxOpenRequests = 16
	kafkaConfig.Consumer.Return.Errors = true
	kafkaConfig.ChannelBufferSize = 64
	kafkaConfig.Version = sarama.V0_9_0_1
	kafkaConfig.ClientID = g.Config().Pull.Kafka.ConsumerID
	kafkaBrokers := g.Config().Pull.Kafka.Brokers
	kafkaTopics := g.Config().Pull.Kafka.Topics

	consumer, err := sarama.NewConsumer(kafkaBrokers, kafkaConfig)
	if err != nil {
		log.Panic(err)
	}

	for _, topic := range kafkaTopics {

		partitionList, err := consumer.Partitions(topic)
		if err != nil {
			log.Panic(err)
		}

		for _, partition := range partitionList {
			offset := loadOffset(topic, partition)
			// offset = sarama.OffsetOldest
			pc, err := consumer.ConsumePartition(topic, partition, offset)
			if err != nil {
				log.Panic(err)
			}

			pcs = append(pcs, pc)
		}
	}
	log.Println("Init kafka partition channels done ...")

	return pcs
}

// should fetch max offset per topic-partition from es
// should return max offset+1
func loadOffset(topic string, partition int32) int64 {
	return sarama.OffsetNewest
}
