package scenarii

import (
	// "bytes"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"sort"
	"strings"
	"time"
)

//Scenario designed to specifically test echo server functionality
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
	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = EC_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	//Successful Difference between quiche and mvfst
	// payload := []byte(fmt.Sprintf("Echo"))
	// payload2 := []byte(fmt.Sprintf("Testing"))
	// payload1 := []byte(fmt.Sprintf("Hello"))
	// payload3 := []byte(fmt.Sprintf("YY"))

	// pp1 := NewProtectedPacket(conn)
	// pp1.Frames = append(pp1.Frames, NewStreamFrame(4, uint64(len(payload))+uint64(len(payload2)), []byte{}, true))

	// pp2 := NewProtectedPacket(conn)
	// pp2.Frames = append(pp2.Frames, NewStreamFrame(4, 0, payload, false))

	// pp3 := NewProtectedPacket(conn)
	// pp3.Frames = append(pp3.Frames, NewStreamFrame(4, 2, payload1, false))

	// pp4 := NewProtectedPacket(conn)
	// pp4.Frames = append(pp4.Frames, NewStreamFrame(4, 2, payload2, false))

	// pp5 := NewProtectedPacket(conn)
	// pp5.Frames = append(pp5.Frames, NewStreamFrame(4, uint64(len(payload2))+2, payload3, true))

	// conn.DoSendPacket(pp1, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp3, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp4, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp5, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp2, EncryptionLevel1RTT)

	//Successful Difference between quiche and mvfst
	payload := []byte(fmt.Sprintf("BLIN"))
	payload2 := []byte(fmt.Sprintf("OCKED"))

	pp1 := NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, NewStreamFrame(4, 7, []byte{}, true))

	pp2 := NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, NewStreamFrame(4, 2, payload2, false))

	pp3 := NewProtectedPacket(conn)
	pp3.Frames = append(pp3.Frames, NewStreamFrame(4, 0, payload, false))

	conn.DoSendPacket(pp1, EncryptionLevel1RTT)
	conn.DoSendPacket(pp2, EncryptionLevel1RTT)
	conn.DoSendPacket(pp3, EncryptionLevel1RTT)

	var streamData string = ""
	streamDataMap := make(map[uint64]string)

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
					streamDataMap[s.StreamId] += string(stream.ReadData)
					// if res := bytes.Compare(stream.ReadData, payload); res != 0 {
					// 	trace.ErrorCode = EC_PayloadChanged
					// 	fmt.Println(string(stream.ReadData))
					// 	fmt.Println("Not the same\n")
					// } else {
					// 	fmt.Println(string(stream.ReadData))
					// 	fmt.Println("No difference\n")
					// }
				}
			}
		case <-conn.ConnectionClosed:
			break forLoop
		case <-s.Timeout():
			break forLoop
		}
	}
	var keys []uint64
	for k, _ := range streamDataMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		streamData += streamDataMap[k]
	}
	fmt.Println("Stream Data: ", streamData)
	trace.Results["StreamDataReassembly"] = streamData
	// if !conn.Streams.Get(0).ReadClosed {
	// 	trace.ErrorCode = EC_HostDidNotRespond
	// }
}
