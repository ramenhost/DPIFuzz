package scenarii

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"strings"
	"time"
)

//Scenario designed to send random bytes to a server after handshake completion.
const (
	UR_TLSHandshakeFailed       = 1
	UR_HostDidNotRespond        = 2
	UR_EndpointDoesNotSupportHQ = 3
)

type UnstructuredRandomScenario struct {
	AbstractScenario
}

func NewUnstructuredRandomScenario() *UnstructuredRandomScenario {
	return &UnstructuredRandomScenario{AbstractScenario{name: "unstructured_random", version: 2}}
}
func (s *UnstructuredRandomScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {

	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = UR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	numPackets := R.Intn(100)

	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	for i := 0; i < numPackets; i++ {
		conn.UdpConnection.Write(RandStringBytes(R.Intn(50)))
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
		trace.ErrorCode = UR_HostDidNotRespond
	}
}
