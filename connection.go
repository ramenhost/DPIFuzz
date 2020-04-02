package quictracker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mpiraux/pigotls"
	"log"
	r "math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
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

	AckQueue map[PNSpace][]PacketNumber // Stores the packet numbers to be acked TODO: This should be a channel actually
	Logger   *log.Logger
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[R.Intn(len(letterBytes))]
	}
	return b
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
		ack_fields := [4]string{"LargestAcknowledged", "AckDelay", "AckRangeCount", "AckRanges"}
		// num := R.Intn(4)
		for i := 0; i < 4; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := ack_fields[R.Intn(4)]; fuzz_field {
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
		reset_fields := [3]string{"StreamId", "ApplicationErrorCode", "FinalSize"}
		for i := 0; i < 3; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := reset_fields[i]; fuzz_field {
				case "StreamId":
					(*frame).(*ResetStream).StreamId = uint64(R.Uint32())
				case "ApplicationErrorCode":
					(*frame).(*ResetStream).ApplicationErrorCode = uint64(R.Uint32())
				case "FinalSize":
					(*frame).(*ResetStream).FinalSize = uint64(R.Uint32())
				}
			}
		}
	case StopSendingType:
		fmt.Println("Fuzzing Stopsending frame")
		stop_fields := [2]string{"StreamId", "ApplicationErrorCode"}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := stop_fields[i]; fuzz_field {
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
		crypto_fields := [3]string{"Offset", "Length", "CryptoData"}
		for i := 0; i < 3; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := crypto_fields[i]; fuzz_field {
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
		stream_fields := [7]string{"FinBit", "LenBit", "OffBit", "StreamId", "Offset", "Length", "StreamData"}
		// num := R.Intn(7)
		for i := 0; i < 7; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := stream_fields[i]; fuzz_field {
				case "FinBit":
					(*frame).(*StreamFrame).FinBit = R.Float32() < 0.5
				case "LenBit":
					(*frame).(*StreamFrame).LenBit = R.Float32() < 0.5
				case "OffBit":
					(*frame).(*StreamFrame).OffBit = R.Float32() < 0.5
				case "StreamId":
					(*frame).(*StreamFrame).StreamId = uint64(R.Uint32())
				case "Offset":
					(*frame).(*StreamFrame).Offset = uint64(R.Uint32())
					// case "Length":
					// 	//does it make sense to fuzz both the length field and the stream data field ? It will definitely lead to a conflict
					// 	(*frame).(*StreamFrame).Length = uint64(R.Uint32())
					// case "StreamData":
					// 	token := make([]byte, len((*frame).(*StreamFrame).StreamData))
					// 	R.Read(token)
					// 	(*frame).(*StreamFrame).StreamData = token

				}
			}

		}
	case MaxDataType:
		fmt.Println("Fuzzing MaxData frame")
		maxData_fields := [1]string{"MaximumData"}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := maxData_fields[i]; fuzz_field {
				case "MaximumData":
					(*frame).(*MaxDataFrame).MaximumData = uint64(R.Uint32())
				}
			}
		}
	// case MaxStreamDataType:
	// 	fmt.Println("Fuzzing MaxStreamData frame")
	// 	maxStreamData_fields := [2]string{"StreamId", "MaximumData"}
	// 	for i := 0; i < 2; i++ {
	// 		if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
	// 			switch fuzz_field := maxStreamData_fields[i]; fuzz_field {
	// 			case "StreamId":
	// 				(*frame).(*MaxStreamDataFrame).StreamId = uint64(R.Uint32())
	// 			case "MaximumData":
	// 				(*frame).(*MaxStreamDataFrame).MaximumStreamData = uint64(R.Uint32())
	// 			}
	// 		}
	// 	}
	case MaxStreamsType:
		fmt.Println("Fuzzing MaxStreams frame")
		maxStream_fields := [2]string{"StreamType", "MaximumStreams"}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := maxStream_fields[i]; fuzz_field {
				case "StreamType":
					(*frame).(*MaxStreamsFrame).StreamsType = R.Float32() < 0.5
				case "MaximumStreams":
					(*frame).(*MaxStreamsFrame).MaximumStreams = uint64(R.Uint32())
				}
			}
		}
	case DataBlockedType:
		fmt.Println("Fuzzing DataBlocked frame")
		dataBlocked_fields := [1]string{"DataLimit"}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := dataBlocked_fields[i]; fuzz_field {
				case "StreamType":
					(*frame).(*DataBlockedFrame).DataLimit = uint64(R.Uint32())
				}
			}
		}
	case StreamDataBlockedType:
		fmt.Println("Fuzzing StreamDataBlocked frame")
		streamDataBlocked_fields := [2]string{"StreamId", "StreamDataLimit"}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := streamDataBlocked_fields[i]; fuzz_field {
				case "StreamId":
					(*frame).(*StreamDataBlockedFrame).StreamId = uint64(R.Uint32())
				case "StreamDataLimit":
					(*frame).(*StreamDataBlockedFrame).StreamDataLimit = uint64(R.Uint32())
				}
			}
		}
	case StreamsBlockedType:
		fmt.Println("Fuzzing StreamsBlocked frame")
		streamBlocked_fields := [2]string{"StreamsType", "StreamLimit"}
		for i := 0; i < 2; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := streamBlocked_fields[i]; fuzz_field {
				case "StreamsType":
					(*frame).(*StreamsBlockedFrame).StreamsType = R.Float32() < 0.5
				case "StreamLimit":
					(*frame).(*StreamsBlockedFrame).StreamLimit = uint64(R.Uint32())
				}
			}
		}
	case NewConnectionIdType:
		fmt.Println("Fuzzing NewConnectionId frame")
		nConId_fields := [5]string{"Sequence", "RetirePriorTo", "Length", "ConnectionId", "StatelessResetToken"}
		for i := 0; i < 5; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := nConId_fields[i]; fuzz_field {
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
		fields := [1]string{"SequenceNumber"}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := fields[i]; fuzz_field {
				case "SequenceNumber":
					(*frame).(*RetireConnectionId).SequenceNumber = uint64(R.Uint32())
				}
			}
		}
	case PathChallengeType:
		fmt.Println("Fuzzing PathChallenge frame")
		fields := [1]string{"Data"}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := fields[i]; fuzz_field {
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
		fields := [1]string{"Data"}
		for i := 0; i < 1; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := fields[i]; fuzz_field {
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
		fields := [4]string{"ErrorCode", "ErrorFrameType", "ReasonPhraseLength", "ReasonPhrase"}
		for i := 0; i < 4; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := fields[i]; fuzz_field {
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
		fields := [3]string{"errorCode", "reasonPhraseLength", "reasonPhrase"}
		for i := 0; i < 3; i++ {
			if fuzz_decision := R.Float32() < 0.5; fuzz_decision {
				switch fuzz_field := fields[i]; fuzz_field {
				case "errorCode":
					(*frame).(*ApplicationCloseFrame).errorCode = uint64(R.Uint32())
				case "reasonPhraseLength":
					(*frame).(*ApplicationCloseFrame).reasonPhraseLength = uint64(R.Uint32())
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

	fuzz_decision := R.Float32() < 0.5
	list := [2]string{"fuzz_payload", "fuzz_frame"}
	action := R.Intn(2)
	if list[action] == "fuzz_frame" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
		fuzz_frame(&packet, level)
	}
	fmt.Println(packet.PNSpace())
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
		if list[action] == "fuzz_payload" && fuzz_decision == true && FuzzSession == true && packet.PNSpace() == PNSpaceAppData {
			payload = fuzz_payload(payload)
		}
		fmt.Println(len(payload))
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

		c.UdpConnection.Write(c.EncodeAndEncrypt(packet, level))

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

	c.Logger = log.New(os.Stderr, fmt.Sprintf("[CID %s] ", hex.EncodeToString(c.OriginalDestinationCID)), log.Lshortfile)

	c.TransitionTo(version, ALPN)

	return c
}
