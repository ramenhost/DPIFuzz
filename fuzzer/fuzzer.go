//Experimental: Designed for modular Fuzzer
package fuzzer

import (
	// "bytes"
	"fmt"
	"sort"
	"strings"

	. "github.com/QUIC-Tracker/quic-tracker"
	g "github.com/QUIC-Tracker/quic-tracker/generators"
	m "github.com/QUIC-Tracker/quic-tracker/mutators"
	// "time"
)

const (
	F_TLSHandshakeFailed       = 1
	F_HostDidNotRespond        = 2
	F_EndpointDoesNotSupportHQ = 3
	F_Timeout                  = 4
	F_HostisAlive              = 5
)

type FuzzerInstance struct {
	AbstractFuzzer
}

func NewFuzzerInstance() *FuzzerInstance {
	return &FuzzerInstance{AbstractFuzzer{name: "FuzzerInstance", version: 2}}
}

func (s *FuzzerInstance) Run(conn *Connection, trace *Trace, preferredPath string, debug bool, generatorName string) {

	//Connection Handler
	flag := 0 //flag used to determine whether host has crashed or not
	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = F_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, F_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	var packetList []*ProtectedPacket
	//Generator
	switch generatorName {
	case "stream_reassembly":
		packetList = g.GenerateStreamReassembly(conn)
	case "flow_control_stream_reassembly":
		packetList = g.GenerateFlowControlStreamReassembly(conn)
	case "overlapping_offset":
		packetList = g.GenerateOverlappingOffset(conn)
		R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })
	}

	defer connAgents.CloseConnection(false, 0, "")
	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	//Mutators
	if generatorName != "overlapping_offset" {
		//Sequence Level
		packetList = m.SequenceLevelMutations(packetList)

		//printing stream frame contents. Comment out if not required
		for _, packet := range packetList {
			for _, f := range packet.Frames {
				if f.FrameType() == StreamType {
					s := f.(*StreamFrame)
					fmt.Println("-*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*")
					fmt.Println("Stream Id:", s.StreamId, " FinBit:", s.FinBit, "Payload: ", string(s.StreamData), "Offset: ", s.Offset, "OffBit:", s.OffBit, "LenBit:", s.LenBit, "Length:", s.Length)
					fmt.Println("-*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*")
				}
			}
		}
		//Packet Level
		newList, payloadList := m.PacketLevelMutations(packetList)

		//Encoder and Encryptor
		for i := 0; i < len(newList); i++ {
			conn.SendFuzzedPacket(newList[i], payloadList[i], EncryptionLevel1RTT)
		}
	} else {
		//printing stream frame contents. Comment out if not required
		for _, packet := range packetList {
			for _, f := range packet.Frames {
				if f.FrameType() == StreamType {
					s := f.(*StreamFrame)
					fmt.Println("-*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*")
					fmt.Println("Stream Id:", s.StreamId, " FinBit:", s.FinBit, "Payload: ", string(s.StreamData), "Offset: ", s.Offset, "OffBit:", s.OffBit, "LenBit:", s.LenBit, "Length:", s.Length)
					fmt.Println("-*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*")
				}
			}
		}
		for i := 0; i < len(packetList); i++ {
			conn.DoSendPacket(packetList[i], EncryptionLevel1RTT)
		}
	}

	//Monitoring IUT Response
	var streamData string = ""
	streamDataMap := make(map[uint64]string)

forLoop:
	for {
		select {
		case i := <-incomingPackets:
			// if conn.Streams.Get(0).ReadClosed {
			// 	s.Finished()
			// }
			if flag == 1 {
				trace.ErrorCode = F_HostisAlive
				continue
			}
			p := i.(Packet)
			if p.PNSpace() == PNSpaceAppData {
				for _, f := range p.(Framer).GetAll(StreamType) {
					s := f.(*StreamFrame)
					stream := conn.Streams.Get(s.StreamId)
					streamDataMap[s.StreamId] += string(stream.ReadData)
				}
			}
		case <-conn.ConnectionClosed: //this is triggered by IdleTimeout. Occurs after s.Timeout(). Checks if host is responding or not
			if trace.ErrorCode == 0 { //check if a packet was received after flag was set to 1
				trace.ErrorCode = F_Timeout
			}
			break forLoop
		case <-s.Timeout(): //triggered by the timeout specified using command line flag. Value < IdleTimeout ensures that this block is hit before conn.ConnectionClosed
			flag = 1
			//send packets which triggers a response
			payload := []byte(fmt.Sprintf("Echo"))
			pp1 := NewProtectedPacket(conn)
			pp1.Frames = append(pp1.Frames, NewStreamFrame(4, uint64(len(payload)), []byte{}, true))
			conn.DoSendPacket(pp1, EncryptionLevel1RTT)
			const ForceVersionNegotiation = 0x1a2a3a4a
			conn.Version = ForceVersionNegotiation
			initial := conn.GetInitialPacket()
			conn.DoSendPacket(initial, EncryptionLevelInitial)
			// trace.ErrorCode = F_Timeout
			//break forLoop
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
	// fmt.Println("Stream Data: ", streamData)
	trace.Results["StreamDataReassembly"] = streamData
	// if !conn.Streams.Get(0).ReadClosed {
	// 	trace.ErrorCode = F_HostDidNotRespond
	// }
}
