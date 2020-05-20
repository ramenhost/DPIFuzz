//Experimental: Designed for modular Fuzzer
package scenarii

import (
	// "bytes"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	g "github.com/QUIC-Tracker/quic-tracker/generators"
	m "github.com/QUIC-Tracker/quic-tracker/mutators"
	"sort"
	"strings"
	// "time"
)

type FuzzerInstance struct {
	AbstractFuzzer
}

func NewFuzzerInstance() *FuzzerInstance {
	return &FuzzerInstance{AbstractFuzzer{name: "FuzzerInstance", version: 2}}
}

func (s *FuzzerInstance) Run(conn *Connection, trace *Trace, preferredPath string, debug bool, generatorName string) {

	//Connection Handler

	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = SR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	var packetList []*ProtectedPacket
	//Generator
	switch generatorName {
	case "stream_reassembly":
		packetList = g.GenerateStreamReassembly(conn)
	case "general_stream_reassembly":
		packetList = g.GenerateGeneralStreamReassembly(conn)
	case "overlapping_offset":
		packetList = g.GenerateOverlappingOffset(conn)

	}

	//Mutators
	//Sequence
	packetList = m.SequenceLevelMutations(packetList)
	//Packet
	newList, payloadList := m.PacketLevelMutations(packetList)

	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	for i := 0; i < len(newList); i++ {
		conn.SendFuzzedPacket(newList[i], payloadList[i], EncryptionLevel1RTT)
	}

	//Monitoring IUT Response
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
	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = SR_HostDidNotRespond
	}
}
