package scenarii

import (
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"strings"

	"time"
)

const (
	EC_TLSHandshakeFailed       = 1
	EC_HostDidNotRespond        = 2
	EC_EndpointDoesNotSupportHQ = 3
	EC_PayloadChanged           = 4
)

type EchoScenario struct {
	AbstractScenario
}

func NewEchoScenario() *EchoScenario {
	return &EchoScenario{AbstractScenario{name: "echo_scenario", version: 2}}
}
func (s *EchoScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {
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

	payload := []byte(fmt.Sprintf("Echo Test. This should be interesting"))

	pp1 := NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, NewStreamFrame(0, 0, payload, false))

	pp2 := NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, NewStreamFrame(0, uint64(len(payload)), []byte{}, true))

	conn.DoSendPacket(pp2, EncryptionLevel1RTT)
	conn.DoSendPacket(pp1, EncryptionLevel1RTT)

forLoop:
	for {
		select {
		case i := <-incomingPackets:
			if conn.Streams.Get(0).ReadClosed {
				s.Finished()
			}

			p := i.(Packet)
			if p.PNSpace() == PNSpaceAppData {
				for _, f := range p.(Framer).GetAll(StreamType) {
					s := f.(*StreamFrame)
					stream := conn.Streams.Get(s.StreamId)
					fmt.Println("Stream Data: ", string(stream.ReadData))
				}
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
