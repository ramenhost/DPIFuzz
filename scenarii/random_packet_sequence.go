package scenarii

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	qt "github.com/QUIC-Tracker/quic-tracker"
)

var li = [4]uint64{0x00, 0x01, 0x02, 0x03}

type RandomPacketSequenceScenario struct {
	AbstractScenario
}

func NewRandomPacketSequenceScenario() *RandomPacketSequenceScenario {
	return &RandomPacketSequenceScenario{AbstractScenario{name: "random_sequence", version: 2}}
}
func (s *RandomPacketSequenceScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
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
	arr := make([]uint64, num_packets)
	for i := 0; i < num_packets; i++ {
		index := rand.Intn(4)
		arr[i] = li[index]
	}

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	for i := 0; i < num_packets; i++ {
		switch c := arr[i]; c {
		case 0x00:
			fmt.Println("VIOLAAAAAAAAAAAAA\n")
			// payload := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))
			// pp3 := qt.NewProtectedPacket(conn)
			// pp3.Frames = append(pp3.Frames, qt.NewStreamFrame(0, 0, payload, false))
			// conn.DoSendPacket(pp3, qt.EncryptionLevel1RTT)
			conn.DoSendPacket(qt.NewInitialPacket(conn), qt.EncryptionLevelInitial)
			// case 0x01:
			// conn.DoSendPacket(qt.NewHandshakePacket(conn), qt.EncryptionLevelHandshake)
			// case 0x02:
			// 	conn.DoSendPacket(qt.NewProtectedPacket(conn), qt.EncryptionLevel1RTT)
			// case 0x03:
			// 	conn.DoSendPacket(qt.NewZeroRTTProtectedPacket(conn), qt.EncryptionLevel0RTT)
		}
	}

	payload := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))

	pp1 := qt.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, qt.NewStreamFrame(0, 0, payload, false))

	pp2 := qt.NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, qt.NewStreamFrame(0, uint64(len(payload)), []byte{}, true))

	conn.DoSendPacket(pp2, qt.EncryptionLevel1RTT)

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
