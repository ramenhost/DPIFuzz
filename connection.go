package quictracker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	// "github.com/jmcvetta/randutil"
	"github.com/mpiraux/pigotls"
	"log"
	r "math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var R *r.Rand
var FuzzSession bool = false

// var r = csrc.NewRandom(true)
// var packet_count int = 0

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	UseIPv6       bool
	Host          *net.UDPAddr
	InterfaceMTU  int

	Tls          *pigotls.Connection
	TLSTPHandler *TLSTransportParameterHandler

	KeyPhaseIndex  uint
	SpinBit        SpinBit
	LastSpinNumber PacketNumber

	CryptoStates map[EncryptionLevel]*CryptoState

	ReceivedPacketHandler func([]byte, unsafe.Pointer)
	SentPacketHandler     func([]byte, unsafe.Pointer)
	RegisterDiffCode      func(string)

	CryptoStreams CryptoStreams // TODO: It should be a parent class without closing states
	Streams       Streams

	IncomingPackets     Broadcaster //type: Packet
	OutgoingPackets     Broadcaster //type: Packet
	IncomingPayloads    Broadcaster //type: IncomingPayload
	UnprocessedPayloads Broadcaster //type: UnprocessedPayload
	EncryptionLevels    Broadcaster //type: DirectionalEncryptionLevel
	FrameQueue          Broadcaster //type: QueuedFrame
	TransportParameters Broadcaster //type: QuicTransportParameters

	PreparePacket      Broadcaster //type: EncryptionLevel
	SendPacket         Broadcaster //type: PacketToSend
	StreamInput        Broadcaster //type: StreamInput
	PacketAcknowledged Broadcaster //type: PacketAcknowledged

	ConnectionClosed    chan bool
	ConnectionRestart   chan bool // Triggered when receiving a Retry or a VN packet
	ConnectionRestarted chan bool

	OriginalDestinationCID ConnectionID
	SourceCID              ConnectionID
	DestinationCID         ConnectionID
	Version                uint32
	ALPN                   string

	Token            []byte
	ResumptionTicket []byte

	PacketNumber           map[PNSpace]PacketNumber // Stores the next PN to be sent
	LargestPNsReceived     map[PNSpace]PacketNumber // Stores the largest PN received
	LargestPNsAcknowledged map[PNSpace]PacketNumber // Stores the largest PN we have sent that were acknowledged by the peer

	MinRTT      uint64
	SmoothedRTT uint64
	RTTVar      uint64
	AckQueue    map[PNSpace][]PacketNumber // Stores the packet numbers to be acked TODO: This should be a channel actually
	Logger      *log.Logger
	QLog        qlog.QLog
	QLogTrace   *qlog.Trace
	QLogEvents  chan *qlog.Event
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890?/><:{}\\()*&^%$#@!_+=,.;'[]"

func RandStringBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[R.Intn(len(letterBytes))]
	}
	return b
}

var MinMaxError = errors.New("Min cannot be greater than max.")

// IntRange returns a random integer in the range from min to max.
func IntRange(min, max int) (int, error) {
	var result int
	switch {
	case min > max:
		// Fail with error
		return result, MinMaxError
	case max == min:
		result = max
	case max > min:
		maxRand := max - min
		b := R.Intn(maxRand)
		result = min + int(b)
	}
	return result, nil
}

type Choice struct {
	Weight int
	Item   interface{}
}

func WeightedChoice(choices []Choice) (Choice, error) {
	var ret Choice
	sum := 0
	for _, c := range choices {
		sum += c.Weight
	}
	r, err := IntRange(0, sum)
	if err != nil {
		return ret, err
	}
	for _, c := range choices {
		r -= c.Weight
		if r < 0 {
			return c, nil
		}
	}
	err = errors.New("Internal error - code should not reach this point")
	return ret, err
}

func (c *Connection) ConnectedIp() net.Addr {
	return c.UdpConnection.RemoteAddr()
}
func (c *Connection) nextPacketNumber(space PNSpace) PacketNumber { // TODO: This should be thread safe
	pn := c.PacketNumber[space]
	c.PacketNumber[space]++
	return pn
}

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
					fmt.Println("Fuzzing Fin")
					(*frame).(*StreamFrame).FinBit = R.Float32() < 0.5
				case "LenBit":
					fmt.Println("Fuzzing lenbit")
					(*frame).(*StreamFrame).LenBit = R.Float32() < 0.5
				case "OffBit":
					fmt.Println("Fuzzing offbit")
					(*frame).(*StreamFrame).OffBit = R.Float32() < 0.5
				//we don't fuzz stream id as it is an easy check which can be used to drop packets
				// case "StreamId":
				// 	(*frame).(*StreamFrame).StreamId = uint64(R.Uint32())
				case "Offset":
					fmt.Println("Fuzzing offset")
					(*frame).(*StreamFrame).Offset = uint64(R.Uint32())
				case "Length":
					fmt.Println("Fuzzing length")
					//does it make sense to fuzz both the length field and the stream data field ? It will definitely lead to a conflict
					(*frame).(*StreamFrame).Length = uint64(R.Uint32())
				case "StreamData":
					fmt.Println("Fuzzing data")
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
		payload = append(payload, rand_payload...)
	}
	return payload
}

func fuzz_frame(packet *Packet, level EncryptionLevel) {
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

func (c *Connection) EncodeAndEncrypt(packet Packet, level EncryptionLevel) []byte {

	// fuzz_decision := R.Float32() < 0.5
	// options := []Choice{{1, "fuzz_payload"}, {2, "fuzz_frame"}}
	// val, err := WeightedChoice(options)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(val.Item)
	// if val.Item == "fuzz_frame" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
	// 	fuzz_frame(&packet, level)
	// }
	// fmt.Println(packet.PNSpace())
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		cryptoState := c.CryptoStates[level]

		payload := packet.EncodePayload()
		// var f []Frame
		// if packet.PNSpace() == PNSpaceInitial {
		// 	frame, err := NewFrame(bytes.NewReader(payload), c)
		// 	if err != nil {
		// 		// spew.Dump(p)
		// 		panic(err)
		// 	}
		// 	f = append(f, frame)
		// }
		// for _, fi := range f {
		// 	fmt.Println(fi.FrameType())
		// }
		// fmt.Println("done")
		// if val.Item == "fuzz_payload" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
		// 	payload = fuzz_payload(payload)
		// }
		// fmt.Println(len(payload))
		if h, ok := packet.Header().(*LongHeader); ok {
			h.Length = NewVarInt(uint64(h.TruncatedPN().Length + len(payload) + cryptoState.Write.Overhead()))
		}

		header := packet.EncodeHeader()
		protectedPayload := cryptoState.Write.Encrypt(payload, uint64(packet.Header().PacketNumber()), header)
		packetBytes := append(header, protectedPayload...)

		firstByteMask := byte(0x1F)
		if packet.Header().PacketType() != ShortHeaderPacket {
			firstByteMask = 0x0F
		}
		sample, pnOffset := GetPacketSample(packet.Header(), packetBytes)
		mask := cryptoState.HeaderWrite.Encrypt(sample, make([]byte, 5, 5))
		packetBytes[0] ^= mask[0] & firstByteMask

		for i := 0; i < packet.Header().TruncatedPN().Length; i++ {
			packetBytes[pnOffset+i] ^= mask[1+i]
		}

		return packetBytes
	default:
		// Clients do not send cleartext packets
	}
	return nil
}

func (c *Connection) EncodeAndEncryptFuzz(packet Packet, level EncryptionLevel) []byte {

	fuzz_decision := R.Float32() < 0.5
	fmt.Println(fuzz_decision)
	options := []Choice{{1, "fuzz_payload"}, {2, "fuzz_frame"}}
	val, err := WeightedChoice(options)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(val.Item)
	if val.Item == "fuzz_frame" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
		fuzz_frame(&packet, level)
	}
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		cryptoState := c.CryptoStates[level]

		payload := packet.EncodePayload()
		if val.Item == "fuzz_payload" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
			payload = fuzz_payload(payload)
		}
		if h, ok := packet.Header().(*LongHeader); ok {
			h.Length = NewVarInt(uint64(h.TruncatedPN().Length + len(payload) + cryptoState.Write.Overhead()))
		}

		header := packet.EncodeHeader()
		protectedPayload := cryptoState.Write.Encrypt(payload, uint64(packet.Header().PacketNumber()), header)
		packetBytes := append(header, protectedPayload...)

		firstByteMask := byte(0x1F)
		if packet.Header().PacketType() != ShortHeaderPacket {
			firstByteMask = 0x0F
		}
		sample, pnOffset := GetPacketSample(packet.Header(), packetBytes)
		mask := cryptoState.HeaderWrite.Encrypt(sample, make([]byte, 5, 5))
		packetBytes[0] ^= mask[0] & firstByteMask

		for i := 0; i < packet.Header().TruncatedPN().Length; i++ {
			packetBytes[pnOffset+i] ^= mask[1+i]
		}

		return packetBytes
	default:
	}
	return nil
}

func (c *Connection) PacketWasSent(packet Packet) {
	if c.SentPacketHandler != nil {
		c.SentPacketHandler(packet.Encode(packet.EncodePayload()), packet.Pointer())
	}
	c.OutgoingPackets.Submit(packet)
}
func (c *Connection) DoSendPacket(packet Packet, level EncryptionLevel) {
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		c.Logger.Printf("Sending packet {type=%s, number=%d}\n", packet.Header().PacketType().String(), packet.Header().PacketNumber())

		packetBytes := c.EncodeAndEncrypt(packet, level)
		c.UdpConnection.Write(packetBytes)
		packet.SetSendContext(PacketContext{Timestamp: time.Now(), RemoteAddr: c.UdpConnection.RemoteAddr(), DatagramSize: uint16(len(packetBytes)), PacketSize: uint16(len(packetBytes))})

		c.PacketWasSent(packet)
	default:
		// Clients do not send cleartext packets
	}
}

func (c *Connection) DoSendPacketFuzz(packet Packet, level EncryptionLevel) {
	// for _, f := range packet.(*ProtectedPacket).Frames {
	// 	s := f.(*StreamFrame)
	// 	fmt.Println("New Testing:", s.StreamId, " FinBit:", s.FinBit, " Payload:", string(s.StreamData), " Offset:", s.Offset)
	// }
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		c.Logger.Printf("Sending packet {type=%s, number=%d}\n", packet.Header().PacketType().String(), packet.Header().PacketNumber())

		packetBytes := c.EncodeAndEncryptFuzz(packet, level)
		c.UdpConnection.Write(packetBytes)
		packet.SetSendContext(PacketContext{Timestamp: time.Now(), RemoteAddr: c.UdpConnection.RemoteAddr(), DatagramSize: uint16(len(packetBytes)), PacketSize: uint16(len(packetBytes))})

		c.PacketWasSent(packet)
	default:
		// Clients do not send cleartext packets
	}
}

//testing adding a spurious initial packet scenario
// func (c *Connection) GetSpuriousInitialPacket(preferredPath string) *InitialPacket {
func (c *Connection) GetSpuriousInitialPacket() *InitialPacket {
	extensionData, err := c.TLSTPHandler.GetExtensionData()
	if err != nil {
		println(err)
		return nil
	}
	c.Tls.SetQUICTransportParameters(extensionData)

	tlsOutput, notComplete, err := c.Tls.HandleMessage(nil, pigotls.EpochInitial)
	if err != nil || !notComplete {
		println(err.Error())
		return nil
	}
	clientHello := tlsOutput[0].Data
	cryptoFrame := NewCryptoFrame(c.CryptoStreams.Get(PNSpaceInitial), clientHello)

	if len(c.Tls.ZeroRTTSecret()) > 0 {
		c.Logger.Printf("0-RTT secret is available, installing crypto state")
		c.CryptoStates[EncryptionLevel0RTT] = NewProtectedCryptoState(c.Tls, nil, c.Tls.ZeroRTTSecret())
		c.EncryptionLevels.Submit(DirectionalEncryptionLevel{EncryptionLevel: EncryptionLevel0RTT, Read: false, Available: true})
	}

	var initialLength int
	if c.UseIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(c)
	initialPacket.Frames = append(initialPacket.Frames, cryptoFrame)
	// payload := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))
	payload := []byte(fmt.Sprintf("GET ./index.html"))
	initialPacket.Frames = append(initialPacket.Frames, NewStreamFrame(0, 0, payload, false))
	initialPacket.PadTo(initialLength - c.CryptoStates[EncryptionLevelInitial].Write.Overhead())

	return initialPacket
}

func (c *Connection) GetInitialPacket() *InitialPacket {
	extensionData, err := c.TLSTPHandler.GetExtensionData()
	if err != nil {
		println(err)
		return nil
	}
	c.Tls.SetQUICTransportParameters(extensionData)

	tlsOutput, notComplete, err := c.Tls.HandleMessage(nil, pigotls.EpochInitial)
	if err != nil || !notComplete {
		println(err.Error())
		return nil
	}
	clientHello := tlsOutput[0].Data
	cryptoFrame := NewCryptoFrame(c.CryptoStreams.Get(PNSpaceInitial), clientHello)

	if len(c.Tls.ZeroRTTSecret()) > 0 {
		c.Logger.Printf("0-RTT secret is available, installing crypto state")
		c.CryptoStates[EncryptionLevel0RTT] = NewProtectedCryptoState(c.Tls, nil, c.Tls.ZeroRTTSecret())
		c.EncryptionLevels.Submit(DirectionalEncryptionLevel{EncryptionLevel: EncryptionLevel0RTT, Read: false, Available: true})
	}

	var initialLength int
	if c.UseIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(c)
	initialPacket.Frames = append(initialPacket.Frames, cryptoFrame)
	initialPacket.PadTo(initialLength - c.CryptoStates[EncryptionLevelInitial].Write.Overhead())

	return initialPacket
}
func (c *Connection) ProcessVersionNegotation(vn *VersionNegotiationPacket) error {
	var version uint32
	for _, v := range vn.SupportedVersions {
		if v >= MinimumVersion && v <= MaximumVersion {
			version = uint32(v)
		}
	}
	if version == 0 {
		c.Logger.Println("No appropriate version was found in the VN packet")
		c.Logger.Printf("Versions received: %v\n", vn.SupportedVersions)
		return errors.New("no appropriate version found")
	}
	QuicVersion = version
	QuicALPNToken = fmt.Sprintf("%s-%02d", strings.Split(c.ALPN, "-")[0], version&0xff)
	_, err := rand.Read(c.DestinationCID)
	c.TransitionTo(QuicVersion, QuicALPNToken)
	return err
}
func (c *Connection) GetAckFrame(space PNSpace) *AckFrame { // Returns an ack frame based on the packet numbers received
	sort.Sort(PacketNumberQueue(c.AckQueue[space]))
	packetNumbers := make([]PacketNumber, 0, len(c.AckQueue[space]))
	if len(c.AckQueue[space]) > 0 {
		last := c.AckQueue[space][0]
		packetNumbers = append(packetNumbers, last)
		for _, i := range c.AckQueue[space] {
			if i != last {
				last = i
				packetNumbers = append(packetNumbers, i)
			}
		}
	}

	if len(packetNumbers) == 0 {
		return nil
	}

	frame := new(AckFrame)
	frame.AckRanges = make([]AckRange, 0, 255)
	frame.LargestAcknowledged = packetNumbers[0]

	previous := frame.LargestAcknowledged
	ackBlock := AckRange{}
	for _, number := range packetNumbers[1:] {
		if previous-number == 1 {
			ackBlock.AckRange++
		} else {
			frame.AckRanges = append(frame.AckRanges, ackBlock)
			ackBlock = AckRange{uint64(previous) - uint64(number) - 2, 0}
		}
		previous = number
	}
	frame.AckRanges = append(frame.AckRanges, ackBlock)
	if len(frame.AckRanges) > 0 {
		frame.AckRangeCount = uint64(len(frame.AckRanges) - 1)
	}
	return frame
}
func (c *Connection) TransitionTo(version uint32, ALPN string) {
	c.TLSTPHandler = NewTLSTransportParameterHandler()
	c.Version = version
	c.ALPN = ALPN
	c.Tls = pigotls.NewConnection(c.ServerName, c.ALPN, c.ResumptionTicket)
	c.PacketNumber = make(map[PNSpace]PacketNumber)
	c.LargestPNsReceived = make(map[PNSpace]PacketNumber)
	c.LargestPNsAcknowledged = make(map[PNSpace]PacketNumber)
	c.AckQueue = make(map[PNSpace][]PacketNumber)
	for _, space := range []PNSpace{PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData} {
		c.PacketNumber[space] = 0
		c.AckQueue[space] = nil
	}

	c.CryptoStates = make(map[EncryptionLevel]*CryptoState)
	c.CryptoStreams = make(map[PNSpace]*Stream)
	c.CryptoStates[EncryptionLevelInitial] = NewInitialPacketProtection(c)
	c.Streams = Streams{streams: make(map[uint64]*Stream), lock: &sync.Mutex{}, input: &c.StreamInput}
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint64, reasonPhrase string) {
	if quicLayer {
		c.FrameQueue.Submit(QueuedFrame{&ConnectionCloseFrame{errCode, 0, uint64(len(reasonPhrase)), reasonPhrase}, EncryptionLevelBest})
	} else {
		c.FrameQueue.Submit(QueuedFrame{&ApplicationCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase}, EncryptionLevelBest})
	}
}
func (c *Connection) SendHTTP09GETRequest(path string, streamID uint64) {
	c.Streams.Send(streamID, []byte(fmt.Sprintf("GET %s\r\n", path)), true)
}
func (c *Connection) Close() {
	c.Tls.Close()
	c.UdpConnection.Close()
}
func EstablishUDPConnection(addr *net.UDPAddr) (*net.UDPConn, error) {
	udpConn, err := net.DialUDP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}
func NewDefaultConnection(address string, serverName string, resumptionTicket []byte, useIPv6 bool, preferredALPN string, negotiateHTTP3 bool) (*Connection, error) {
	scid := make([]byte, 8, 8)
	dcid := make([]byte, 8, 8)
	rand.Read(scid)
	rand.Read(dcid)

	var network string
	if useIPv6 {
		network = "udp6"
	} else {
		network = "udp4"
	}

	udpAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	udpConn, err := EstablishUDPConnection(udpAddr)
	if err != nil {
		return nil, err
	}

	var c *Connection
	if negotiateHTTP3 {
		c = NewConnection(serverName, QuicVersion, QuicH3ALPNToken, scid, dcid, udpConn, resumptionTicket)
	} else {
		QuicALPNToken = fmt.Sprintf("%s-%02d", preferredALPN, QuicVersion&0xff)
		c = NewConnection(serverName, QuicVersion, QuicALPNToken, scid, dcid, udpConn, resumptionTicket)
	}

	var headerOverhead = 8
	if useIPv6 {
		headerOverhead += 40
	} else {
		headerOverhead += 20
	}

	lAddr := udpConn.LocalAddr().(*net.UDPAddr)
	itfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

findMTU:
	for _, e := range itfs {
		addrs, err := e.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			switch ipNet := a.(type) {
			case *net.IPNet:
				if ipNet.IP.Equal(lAddr.IP) {
					c.InterfaceMTU = e.MTU
					c.TLSTPHandler.MaxPacketSize = uint64(c.InterfaceMTU - headerOverhead)
					break findMTU
				}
			}
		}
	}

	c.UseIPv6 = useIPv6
	c.Host = udpAddr
	return c, nil
}

func NewConnection(serverName string, version uint32, ALPN string, SCID []byte, DCID []byte, udpConn *net.UDPConn, resumptionTicket []byte) *Connection {
	c := new(Connection)
	c.ServerName = serverName
	c.UdpConnection = udpConn
	c.SourceCID = SCID
	c.DestinationCID = DCID
	c.OriginalDestinationCID = DCID

	c.ResumptionTicket = resumptionTicket

	c.IncomingPackets = NewBroadcaster(1000)
	c.OutgoingPackets = NewBroadcaster(1000)
	c.IncomingPayloads = NewBroadcaster(1000)
	c.UnprocessedPayloads = NewBroadcaster(1000)
	c.EncryptionLevels = NewBroadcaster(10)
	c.FrameQueue = NewBroadcaster(1000)
	c.TransportParameters = NewBroadcaster(10)
	c.ConnectionClosed = make(chan bool, 1)
	c.ConnectionRestart = make(chan bool, 1)
	c.ConnectionRestarted = make(chan bool, 1)
	c.PreparePacket = NewBroadcaster(1000)
	c.SendPacket = NewBroadcaster(1000)
	c.StreamInput = NewBroadcaster(1000)
	c.PacketAcknowledged = NewBroadcaster(1000)

	c.QLog.Version = "draft-01"
	c.QLog.Description = "QUIC-Tracker"
	if len(GitCommit()) > 0 {
		c.QLog.Description += " commit " + GitCommit()
	}
	c.QLogTrace = &qlog.Trace{}
	c.QLog.Traces = append(c.QLog.Traces, c.QLogTrace)

	c.QLogTrace.VantagePoint.Name = "QUIC-Tracker"
	c.QLogTrace.VantagePoint.Type = "client"
	c.QLogTrace.Description = fmt.Sprintf("Connection to %s (%s), using version %08x and alpn %s", serverName, udpConn.RemoteAddr().String(), version, ALPN)
	c.QLogTrace.ReferenceTime = time.Now()
	c.QLogTrace.Configuration.TimeUnits = qlog.TimeUnitsString

	c.QLogTrace.CommonFields = make(map[string]interface{})
	c.QLogTrace.CommonFields["ODCID"] = hex.EncodeToString(c.OriginalDestinationCID)
	c.QLogTrace.CommonFields["group_id"] = c.QLogTrace.CommonFields["ODCID"]
	c.QLogTrace.CommonFields["reference_time"] = c.QLogTrace.ReferenceTime.UnixNano() / int64(qlog.TimeUnits)
	c.QLogTrace.EventFields = qlog.DefaultEventFields()
	c.QLogEvents = make(chan *qlog.Event, 1000)

	go func() {
		for e := range c.QLogEvents {
			c.QLogTrace.Add(e)
		}
	}()

	c.Logger = log.New(os.Stderr, fmt.Sprintf("[CID %s] ", hex.EncodeToString(c.OriginalDestinationCID)), log.Lshortfile)

	c.TransitionTo(version, ALPN)

	return c
}
