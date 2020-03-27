package scenarii

import (
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"strings"

	"time"
)

type StreamResetReorderingScenario struct {
	AbstractScenario
}

func GenerateResetStream(payload []byte) *(qt.ResetStream) {
	frame := new(qt.ResetStream)
	// _, _ = ReadVarInt(buffer) // Discard frame type
	frame.StreamId = 0
	frame.ApplicationErrorCode = 2
	frame.FinalSize = uint64(len(payload))
	return frame
}

func NewStreamResetReorderingScenario() *StreamResetReorderingScenario {
	return &StreamResetReorderingScenario{AbstractScenario{name: "stream_reset_reordering", version: 2}}
}
func (s *StreamResetReorderingScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
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

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	payload := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))

	pp1 := qt.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, qt.NewStreamFrame(0, 0, payload, false))

	pp2 := qt.NewProtectedPacket(conn)
	// pp2.Frames = append(pp2.Frames, qt.NewStreamFrame(0, uint64(len(payload)), []byte{}, true))
	resetStream := qt.Frame(GenerateResetStream(payload))
	pp2.Frames = append(pp2.Frames, resetStream)

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
