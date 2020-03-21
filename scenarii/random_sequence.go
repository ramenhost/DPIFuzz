package scenarii

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"time"

	qt "github.com/QUIC-Tracker/quic-tracker"
)

// const (
// 	SOR_TLSHandshakeFailed       = 1
// 	SOR_HostDidNotRespond        = 2
// 	SOR_EndpointDoesNotSupportHQ = 3
// )

var list = [22]qt.FrameType{qt.PaddingFrameType, qt.PingType, qt.AckType, qt.AckECNType, qt.ResetStreamType, qt.StopSendingType, qt.CryptoType, qt.NewTokenType, qt.RetireConnectionIdType, qt.PathChallengeType, qt.PathResponseType, qt.ConnectionCloseType, qt.ApplicationCloseType, qt.HandshakeDoneType}

type RandomSequenceScenario struct {
	AbstractScenario
}

func NewRandomSequenceScenario() *RandomSequenceScenario {
	return &RandomSequenceScenario{AbstractScenario{name: "random_sequence", version: 2}}
}
func (s *RandomSequenceScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	if !strings.Contains(conn.ALPN, "hq") {
		trace.ErrorCode = SOR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	num_packets := rand.Intn(20)
	arr := make([]qt.FrameType, num_packets)
	for i := 0; i < num_packets; i++ {
		index := rand.Intn(22)
		arr[i] = list[index]
	}
	packet_list := make([]*(qt.ProtectedPacket), num_packets)
	for i := 0; i < num_packets; i++ {
		packet_list[i] = qt.NewProtectedPacket(conn)
		switch c := arr[i]; c {
		case 0x00:
			paddingFrame := qt.NewPaddingFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, paddingFrame)
		case 0x01:
			pingFrame := qt.NewPingFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, pingFrame)
		case 0x02:
			ackFrame := qt.ReadAckFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, ackFrame)
		case 0x03:
			ackECNFrame := qt.ReadAckECNFrame(bytes.NewReader([]byte{}), conn)
			packet_list[i].Frames = append(packet_list[i].Frames, ackECNFrame)
		case 0x04:
			resetStream := qt.NewResetStream(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, resetStream)
		case 0x05:
			stopSendingFrame := qt.NewStopSendingFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, stopSendingFrame)
		case 0x06:
			cryptoFrame := qt.NewCryptoFrame(conn.CryptoStreams.Get(qt.PNSpaceInitial), []byte{})
			packet_list[i].Frames = append(packet_list[i].Frames, cryptoFrame)
		case 0x07:
			readNewToken := qt.ReadNewTokenFrame(bytes.NewReader([]byte{}), conn)
			packet_list[i].Frames = append(packet_list[i].Frames, readNewToken)
		case 0x08:
			readStream := qt.ReadStreamFrame(bytes.NewReader([]byte{}), conn)
			packet_list[i].Frames = append(packet_list[i].Frames, readStream)
		case 0x10:
			newMaxData := qt.NewMaxDataFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newMaxData)
		case 0x11:
			newMaxStreamData := qt.NewMaxStreamDataFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newMaxStreamData)
		case 0x12:
			newMaxStreamId := qt.NewMaxStreamIdFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newMaxStreamId)
		case 0x14:
			newBlocked := qt.NewBlockedFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newBlocked)
		case 0x15:
			newStreamBlocked := qt.NewStreamBlockedFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newStreamBlocked)
		case 0x16:
			newStreamIdNeeded := qt.NewStreamIdNeededFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newStreamIdNeeded)
		case 0x18:
			newConnectionId := qt.NewNewConnectionIdFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, newConnectionId)
		case 0x19:
			readRetireConnectionId := qt.ReadRetireConnectionId(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, readRetireConnectionId)
		case 0x1a:
			readPathChallenge := qt.ReadPathChallenge(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, readPathChallenge)
		case 0x1b:
			readPathResponse := qt.ReadPathResponse(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, readPathResponse)
		case 0x1c:
			connectionClose := qt.NewConnectionCloseFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, connectionClose)
		case 0x1d:
			applicationClose := qt.NewApplicationCloseFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, applicationClose)
		case 0x1e:
			handshakeDoneFrame := qt.NewHandshakeDoneFrame(bytes.NewReader([]byte{}))
			packet_list[i].Frames = append(packet_list[i].Frames, handshakeDoneFrame)
		}
	}

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	payload := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))

	pp1 := qt.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, qt.NewStreamFrame(0, 0, payload, false))

	pp2 := qt.NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, qt.NewStreamFrame(0, uint64(len(payload)), []byte{}, true))

	conn.DoSendPacket(pp2, qt.EncryptionLevel1RTT)

	for i := 0; i < num_packets; i++ {
		conn.DoSendPacket(packet_list[i], qt.EncryptionLevel1RTT)
	}

	conn.DoSendPacket(pp1, qt.EncryptionLevel1RTT)

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
