package scenarii

// import (
// 	qt "github.com/QUIC-Tracker/quic-tracker"

// 	"github.com/QUIC-Tracker/quic-tracker/agents"
// )

// type SpuriousInitialPacketScenario struct {
// 	AbstractScenario
// }

// func NewSpuriousInitialPacketScenario() *SpuriousInitialPacketScenario {
// 	return &SpuriousInitialPacketScenario{AbstractScenario{name: "spurious_initial_packet", version: 2}}
// }

// func (s *SpuriousInitialPacketScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
// 	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
// 	defer connAgents.StopAll()

// 	incPackets := conn.IncomingPackets.RegisterNewChan(1000)
// 	initial := conn.GetSpuriousInitialPacket(preferredPath)
// 	conn.DoSendPacket(initial, qt.EncryptionLevelInitial)

// 	for{
// 		select{
// 		case i := <-incPackets
// 		}
// 	}
// }

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

	"github.com/QUIC-Tracker/quic-tracker/agents"
)

type SpuriousInitialPacketScenario struct {
	AbstractScenario
}

func NewSpuriousInitialPacketScenario() *SpuriousInitialPacketScenario {
	return &SpuriousInitialPacketScenario{AbstractScenario{name: "spurious_initial_packet", version: 2}}
}

// type HandshakeScenario struct {
// 	AbstractScenario
// }

// func NewHandshakeScenario() *HandshakeScenario {
// 	return &HandshakeScenario{AbstractScenario{name: "handshake", version: 2}}
// }
func (s *SpuriousInitialPacketScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)
	connAgents.Get("SendingAgent").(*agents.SendingAgent).FrameProducer = connAgents.GetFrameProducingAgents()

	handshakeStatus := handshakeAgent.HandshakeStatus.RegisterNewChan(1000)
	handshakeAgent.InitiateHandshake()

	var status agents.HandshakeStatus
	for {
		select {
		case i := <-handshakeStatus:
			status = i.(agents.HandshakeStatus)
			if !status.Completed {
				switch status.Error.Error() {
				case "no appropriate version found":
					trace.MarkError(H_NoCompatibleVersionAvailable, status.Error.Error(), status.Packet)
				case "received incorrect packet type during handshake":
					trace.MarkError(H_ReceivedUnexpectedPacketType, "", status.Packet)
				default:
					trace.MarkError(H_TLSHandshakeFailed, status.Error.Error(), status.Packet)
				}
			} else {
				trace.Results["negotiated_version"] = conn.Version
			}
			handshakeAgent.HandshakeStatus.Unregister(handshakeStatus)
			s.Finished()
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			if !status.Completed {
				if trace.ErrorCode == 0 {
					trace.MarkError(H_Timeout, "", nil)
				}
				connAgents.StopAll()
			} else {
				connAgents.CloseConnection(false, 0, "")
			}
			return
		}
	}
}
