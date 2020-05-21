package scenarii

import (
	// "bytes"
	// "fmt"
	"math/rand"
	"strings"
	// "time"

	. "github.com/QUIC-Tracker/quic-tracker"
)

// const (
// 	SOR_TLSHandshakeFailed       = 1
// 	SOR_HostDidNotRespond        = 2
// 	SOR_EndpointDoesNotSupportHQ = 3
// )

var list = [22]FrameType{PaddingFrameType, PingType, AckType, AckECNType, ResetStreamType, StopSendingType, CryptoType, NewTokenType, RetireConnectionIdType, PathChallengeType, PathResponseType, ConnectionCloseType, ApplicationCloseType, HandshakeDoneType}

type RandomSequenceScenario struct {
	AbstractScenario
}

func NewRandomSequenceScenario() *RandomSequenceScenario {
	return &RandomSequenceScenario{AbstractScenario{name: "random_sequence", version: 2}}
}
func (s *RandomSequenceScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {
	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = SOR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	numProtectedPackets := rand.Intn(20)
	var arr []FrameType
	for i := 0; i < numProtectedPackets; i++ {
		index := rand.Intn(22)
		arr = append(arr, list[index])
	}
	var packet_list []*ProtectedPacket
	for i := 0; i < numProtectedPackets; i++ {
		packet_list = append(packet_list, NewProtectedPacket(conn))
		switch c := arr[i]; c {
		case 0x00:
			paddingFrame := new(PaddingFrame)
			packet_list[i].Frames = append(packet_list[i].Frames, paddingFrame)
		case 0x01:
			pingFrame := new(PingFrame)
			packet_list[i].Frames = append(packet_list[i].Frames, pingFrame)
		case 0x02:
			ackFrame := new(AckFrame)
			ackFrame.LargestAcknowledged = PacketNumber(R.Intn(10))
			ackFrame.AckDelay = uint64(R.Intn(10))
			ackFrame.AckRangeCount = uint64(R.Intn(10))

			firstBlock := AckRange{}
			firstBlock.AckRange = uint64(R.Intn(10))
			ackFrame.AckRanges = append(ackFrame.AckRanges, firstBlock)

			var j uint64
			for j = 0; j < ackFrame.AckRangeCount; j++ {
				ack := AckRange{}
				ack.Gap = uint64(R.Intn(10))
				ack.AckRange = uint64(R.Intn(10))
				ackFrame.AckRanges = append(ackFrame.AckRanges, ack)
			}
			packet_list[i].Frames = append(packet_list[i].Frames, ackFrame)
		case 0x03:
			ackFrame := new(AckFrame)
			ackFrame.LargestAcknowledged = PacketNumber(R.Intn(10))
			ackFrame.AckDelay = uint64(R.Intn(10))
			ackFrame.AckRangeCount = uint64(R.Intn(10))

			firstBlock := AckRange{}
			firstBlock.AckRange = uint64(R.Intn(10))
			ackFrame.AckRanges = append(ackFrame.AckRanges, firstBlock)

			var j uint64
			for j = 0; j < ackFrame.AckRangeCount; j++ {
				ack := AckRange{}
				ack.Gap = uint64(R.Intn(10))
				ack.AckRange = uint64(R.Intn(10))
				ackFrame.AckRanges = append(ackFrame.AckRanges, ack)
			}
			frame := &AckECNFrame{*ackFrame, 0, 0, 0}

			frame.ECT0Count = uint64(R.Intn(10))
			frame.ECT1Count = uint64(R.Intn(10))
			frame.ECTCECount = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x04:
			resetFrame := new(ResetStream)
			resetFrame.StreamId = uint64(R.Intn(10))
			resetFrame.ApplicationErrorCode = uint64(R.Intn(10))
			resetFrame.FinalSize = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, resetFrame)
		case 0x05:
			frame := new(StopSendingFrame)
			frame.StreamId = uint64(R.Intn(10))
			frame.ApplicationErrorCode = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x06:
			frame := &CryptoFrame{Offset: uint64(R.Intn(10)), CryptoData: RandStringBytes(10), Length: uint64(R.Intn(10))}
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x07:
			frame := new(NewTokenFrame)
			tokenLength := uint64(R.Intn(10))
			frame.Token = make([]byte, tokenLength)
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x08:
			frame := NewStreamFrame(uint64(R.Intn(10)), uint64(R.Intn(10)), RandStringBytes(10), R.Float32() < 0.5)
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x10:
			frame := new(MaxDataFrame)
			frame.MaximumData = uint64(R.Intn(100))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x11:
			frame := new(MaxStreamDataFrame)
			frame.StreamId = uint64(R.Intn(10))
			frame.MaximumStreamData = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x12:
			frame := new(MaxStreamsFrame)
			frame.MaximumStreams = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x14:
			frame := new(DataBlockedFrame)
			frame.DataLimit = uint64(R.Intn(100))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x15:
			frame := new(StreamDataBlockedFrame)
			frame.StreamId = uint64(R.Intn(10))
			frame.StreamDataLimit = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x16:
			frame := new(StreamsBlockedFrame)
			frame.StreamLimit = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x18:
			frame := new(NewConnectionIdFrame)
			frame.Sequence = uint64(R.Intn(10))
			frame.RetirePriorTo = uint64(R.Intn(10))
			frame.Length = uint8(R.Intn(10))
			frame.ConnectionId = make([]byte, frame.Length, frame.Length)
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x19:
			frame := new(RetireConnectionId)
			frame.SequenceNumber = uint64(R.Intn(10))
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x1a:
			frame := new(PathChallenge)
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x1b:
			frame := new(PathResponse)
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x1c:
			frame := new(ConnectionCloseFrame)
			frame.ErrorCode = uint64(R.Intn(10))
			frame.ErrorFrameType = uint64(R.Intn(10))
			frame.ReasonPhraseLength = uint64(R.Intn(10))
			if frame.ReasonPhraseLength > 0 {
				reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
				frame.ReasonPhrase = string(reasonBytes)
			}
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x1d:
			frame := new(ApplicationCloseFrame)
			frame.ErrorCode = uint64(R.Intn(10))
			frame.ReasonPhraseLength = uint64(R.Intn(10))
			if frame.ReasonPhraseLength > 0 {
				reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
				frame.ReasonPhrase = string(reasonBytes)
			}
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		case 0x1e:
			frame := new(HandshakeDoneFrame)
			packet_list[i].Frames = append(packet_list[i].Frames, frame)
		}
	}

	for i := 0; i < numProtectedPackets; i++ {
		conn.DoSendPacketFuzz(packet_list[i], EncryptionLevel1RTT)
	}

forLoop:
	for {
		select {
		case <-incomingPackets:
			if conn.Streams.Get(0).ReadClosed {
				s.Finished()
			}
		case <-conn.ConnectionClosed:
			break forLoop
		case <-s.Timeout():
			break forLoop
		}
	}

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = SOR_HostDidNotRespond
	}
}
