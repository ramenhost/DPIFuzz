package mutators

import (
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
)

func fuzz_individual_frame(frame *Frame) {

	switch (*frame).FrameType() {
	case PaddingFrameType:
		// fmt.Println("Can't fuzz padding frame")
	case PingType:
		// fmt.Println("Can't fuzz ping frame")
	case AckType:
		fmt.Println("Fuzzing ACK Frame")
		ack_fields := []Choice{{1, "LargestAcknowledged"}, {1, "AckDelay"}, {1, "AckRangeCount"}, {1, "AckRanges"}}
		// num := R.Intn(4)
		for i := 0; i < 4; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(ack_fields); fuzz_field.Item {
				case "LargestAcknowledged":
					(*frame).(*AckFrame).LargestAcknowledged = PacketNumber(uint64(R.Uint32()))
				case "AckDelay":
					(*frame).(*AckFrame).AckDelay = uint64(R.Uint32())
				case "AckRangeCount":
					(*frame).(*AckFrame).AckRangeCount = uint64(R.Uint32())
				case "AckRanges":
					for i, _ := range (*frame).(*AckFrame).AckRanges {
						(*frame).(*AckFrame).AckRanges[i].Gap = uint64(R.Uint32())
						(*frame).(*AckFrame).AckRanges[i].AckRange = uint64(R.Uint32())
					}
				}
			}
		}
	case AckECNType:
	case ResetStreamType:
		fmt.Println("Fuzzing Reset Stream")
		reset_fields := []Choice{{1, "StreamId"}, {1, "ApplicationErrorCode"}, {1, "FinalSize"}}
		for i := 0; i < 3; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(reset_fields); fuzz_field.Item {
				//we don't fuzz stream id as it is an easy check which can be used to drop packets
				// case "StreamId":
				// 	(*frame).(*ResetStream).StreamId = uint64(R.Uint32())
				case "ApplicationErrorCode":
					(*frame).(*ResetStream).ApplicationErrorCode = uint64(R.Uint32())
				case "FinalSize":
					(*frame).(*ResetStream).FinalSize = uint64(R.Uint32())
				}
			}
		}
	case StopSendingType:
		fmt.Println("Fuzzing Stopsending frame")
		stop_fields := []Choice{{1, "StreamId"}, {1, "ApplicationErrorCode"}}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(stop_fields); fuzz_field.Item {
				case "StreamId":
					(*frame).(*StopSendingFrame).StreamId = uint64(R.Uint32())
				case "ApplicationErrorCode":
					(*frame).(*StopSendingFrame).ApplicationErrorCode = uint64(R.Uint32())
				}
			}
		}
	case CryptoType:
		//fuzzing the crypto frame might stop the handshake from getting completed. Should we fuzz it anyway ?
		fmt.Println("Fuzzing Crypto frame")
		crypto_fields := []Choice{{1, "Offset"}, {1, "Length"}, {1, "CryptoData"}}
		for i := 0; i < 3; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(crypto_fields); fuzz_field.Item {
				case "Offset":
					(*frame).(*CryptoFrame).Offset = uint64(R.Uint32())
					//should we fuzz the next two fields ?
				case "Length":
				case "CryptoData":
				}
			}
		}
	case NewTokenType:
	case StreamType:
		fmt.Println("Fuzzing Stream Frame")
		stream_fields := []Choice{{1, "FinBit"}, {1, "LenBit"}, {1, "OffBit"}, {1, "StreamId"}, {1, "Offset"}, {1, "Length"}, {1, "StreamData"}}
		// num := R.Intn(7)
		for i := 0; i < 7; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(stream_fields); fuzz_field.Item {
				case "FinBit":
					(*frame).(*StreamFrame).FinBit = R.Float32() < 0.5
				case "LenBit":
					(*frame).(*StreamFrame).LenBit = R.Float32() < 0.5
				case "OffBit":
					(*frame).(*StreamFrame).OffBit = R.Float32() < 0.5
				//we don't fuzz stream id as it is an easy check which can be used to drop packets
				// case "StreamId":
				// 	(*frame).(*StreamFrame).StreamId = uint64(R.Uint32())
				case "Offset":
					(*frame).(*StreamFrame).Offset = uint64(R.Uint32())
				case "Length":
					//does it make sense to fuzz both the length field and the stream data field ? It will definitely lead to a conflict
					(*frame).(*StreamFrame).Length = uint64(R.Uint32())
				case "StreamData":
					token := make([]byte, len((*frame).(*StreamFrame).StreamData))
					R.Read(token)
					(*frame).(*StreamFrame).StreamData = token

				}
			}

		}
	case MaxDataType:
		fmt.Println("Fuzzing MaxData frame")
		maxData_fields := []Choice{{1, "MaximumData"}}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(maxData_fields); fuzz_field.Item {
				case "MaximumData":
					(*frame).(*MaxDataFrame).MaximumData = uint64(R.Uint32())
				}
			}
		}
	case MaxStreamDataType:
		fmt.Println("Fuzzing MaxStreamData frame")
		maxStreamData_fields := []Choice{{1, "StreamId"}, {1, "MaximumData"}}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(maxStreamData_fields); fuzz_field.Item {
				case "StreamId":
					(*frame).(*MaxStreamDataFrame).StreamId = uint64(R.Uint32())
				case "MaximumData":
					(*frame).(*MaxStreamDataFrame).MaximumStreamData = uint64(R.Uint32())
				}
			}
		}
	case MaxStreamsType:
		fmt.Println("Fuzzing MaxStreams frame")
		maxStream_fields := []Choice{{1, "StreamType"}, {1, "MaximumStreams"}}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(maxStream_fields); fuzz_field.Item {
				case "StreamType":
					(*frame).(*MaxStreamsFrame).StreamsType = R.Float32() < 0.5
				case "MaximumStreams":
					(*frame).(*MaxStreamsFrame).MaximumStreams = uint64(R.Uint32())
				}
			}
		}
	case DataBlockedType:
		fmt.Println("Fuzzing DataBlocked frame")
		dataBlocked_fields := []Choice{{1, "DataLimit"}}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(dataBlocked_fields); fuzz_field.Item {
				case "DataLimit":
					(*frame).(*DataBlockedFrame).DataLimit = uint64(R.Uint32())
				}
			}
		}
	case StreamDataBlockedType:
		fmt.Println("Fuzzing StreamDataBlocked frame")
		streamDataBlocked_fields := []Choice{{1, "StreamId"}, {1, "StreamDataLimit"}}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(streamDataBlocked_fields); fuzz_field.Item {
				//we don't fuzz stream id as it is an easy check which can be used to drop packets
				// case "StreamId":
				// 	(*frame).(*StreamDataBlockedFrame).StreamId = uint64(R.Uint32())
				case "StreamDataLimit":
					(*frame).(*StreamDataBlockedFrame).StreamDataLimit = uint64(R.Uint32())
				}
			}
		}
	case StreamsBlockedType:
		fmt.Println("Fuzzing StreamsBlocked frame")
		streamBlocked_fields := []Choice{{1, "StreamsType"}, {1, "StreamLimit"}}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(streamBlocked_fields); fuzz_field.Item {
				case "StreamsType":
					(*frame).(*StreamsBlockedFrame).StreamsType = R.Float32() < 0.5
				case "StreamLimit":
					(*frame).(*StreamsBlockedFrame).StreamLimit = uint64(R.Uint32())
				}
			}
		}
	case NewConnectionIdType:
		fmt.Println("Fuzzing NewConnectionId frame")
		nConId_fields := []Choice{{1, "Sequence"}, {1, "RetirePriorTo"}, {1, "Length"}, {1, "ConnectionId"}, {1, "StatelessResetToken"}}
		for i := 0; i < 5; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(nConId_fields); fuzz_field.Item {
				case "Sequence":
					(*frame).(*NewConnectionIdFrame).Sequence = uint64(R.Uint32())
				case "RetirePriorTo":
					(*frame).(*NewConnectionIdFrame).RetirePriorTo = uint64(R.Uint32())
				case "Length":
					(*frame).(*NewConnectionIdFrame).Length = uint8(R.Intn(255))
				case "ConnectionId":
				case "StatelessResetToken":
					for j := 0; j < 16; j++ {
						token := make([]byte, 1)
						R.Read(token)
						(*frame).(*NewConnectionIdFrame).StatelessResetToken[j] = token[0]
					}
				}
			}
		}
	case RetireConnectionIdType:
		fmt.Println("Fuzzing RetireConnectionId frame")
		fields := []Choice{{1, "SequenceNumber"}}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(fields); fuzz_field.Item {
				case "SequenceNumber":
					(*frame).(*RetireConnectionId).SequenceNumber = uint64(R.Uint32())
				}
			}
		}
	case PathChallengeType:
		fmt.Println("Fuzzing PathChallenge frame")
		fields := []Choice{{1, "Data"}}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(fields); fuzz_field.Item {
				case "Data":
					for j := 0; j < 16; j++ {
						token := make([]byte, 1)
						R.Read(token)
						(*frame).(*PathChallenge).Data[j] = token[0]
					}
				}
			}
		}
	case PathResponseType:
		fmt.Println("Fuzzing PathResponse frame")
		fields := []Choice{{1, "Data"}}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(fields); fuzz_field.Item {
				case "Data":
					for j := 0; j < 16; j++ {
						token := make([]byte, 1)
						R.Read(token)
						(*frame).(*PathResponse).Data[j] = token[0]
					}
				}
			}
		}
	case ConnectionCloseType:
		fmt.Println("Fuzzing ConnectionClose frame")
		fields := []Choice{{1, "ErrorCode"}, {1, "ErrorFrameType"}, {1, "ReasonPhraseLength"}, {1, "ReasonPhrase"}}
		for i := 0; i < 4; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(fields); fuzz_field.Item {
				case "ErrorCode":
					(*frame).(*ConnectionCloseFrame).ErrorCode = uint64(R.Uint32())
				case "ErrorFrameType":
					(*frame).(*ConnectionCloseFrame).ErrorFrameType = uint64(R.Uint32())
				case "ReasonPhraseLength":
					(*frame).(*ConnectionCloseFrame).ReasonPhraseLength = uint64(R.Uint32())
				case "ReasonPhrase":
					//could this lead to memory overlap problems ?
					// (*frame).(*ConnectionCloseFrame).ReasonPhrase = string(RandStringBytes(R.Intn(100)))
				}
			}
		}
	case ApplicationCloseType:
		fmt.Println("Fuzzing ApplicationClose frame")
		fields := []Choice{{1, "errorCode"}, {1, "reasonPhraseLength"}, {1, "reasonPhrase"}}
		for i := 0; i < 3; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field, _ := WeightedChoice(fields); fuzz_field.Item {
				case "errorCode":
					(*frame).(*ApplicationCloseFrame).ErrorCode = uint64(R.Uint32())
				case "reasonPhraseLength":
					(*frame).(*ApplicationCloseFrame).ReasonPhraseLength = uint64(R.Uint32())
				case "reasonPhrase":
					//could this lead to memory overlap problems ?
					// (*frame).(*ApplicationCloseFrame).reasonPhrase = string(RandStringBytes(R.Intn(100)))
				}
			}
		}
	case HandshakeDoneType:
	}
}

func fuzz_payload(payload []byte) []byte {
	fmt.Println("fuzzing payload")
	list := [3]string{"repeat_payload", "alter_payload", "add_random_payload"}
	//test whether math/rand is the right choice for our purpose or not
	index := R.Intn(3)
	switch list[index] {
	case "repeat_payload":
		fmt.Println("repeating payload")
		payload = append(payload, payload...)

	case "alter_payload":
		fmt.Println("altering payload")
		for i, _ := range payload {
			fuzz_decision := R.Float32() < 0.5
			switch fuzz_decision {
			case true:
				token := make([]byte, 1)
				R.Read(token)
				payload[i] = token[0]
			}
		}
	case "add_random_payload":
		fmt.Println("adding random payload")
		rand_payload := RandStringBytes(R.Intn(200))
		fmt.Println(rand_payload)
		payload = append(payload, rand_payload...)
	}
	return payload
}

func fuzz_frame(packet *Packet) {
	//need to add cases for packets like
	fmt.Println("fuzzing frame")
	frames := (*packet).(Framer).GetFrames()
	for i, _ := range frames {
		fuzz_decision := R.Float32() < 0.5
		if fuzz_decision == true {
			fuzz_individual_frame(&((*packet).(Framer).GetFrames()[i]))
		}
		// fmt.Println(f.FrameType())
	}
}

func mutatePacket(packet Packet) (Packet, []byte) {
	fuzz_decision := R.Float32() < 0.5
	options := []Choice{{1, "fuzz_payload"}, {2, "fuzz_frame"}}
	val, err := WeightedChoice(options)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(val.Item)
	if val.Item == "fuzz_frame" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
		fuzz_frame(&packet)
	}
	payload := packet.EncodePayload()
	if val.Item == "fuzz_payload" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
		payload = fuzz_payload(payload)
	}
	return packet, payload
}

func PacketLevelMutations(packetList []*ProtectedPacket) ([]*ProtectedPacket, [][]byte) {
	count := 0
	var payloadList [][]byte
	var newPacketList []Packet
	for _, packet := range packetList {
		new_packet, payload := mutatePacket(packet)
		newPacketList = append(newPacketList, new_packet)
		payloadList = append(payloadList, payload)
		count = count + 1
	}
	return packetList, payloadList
}
