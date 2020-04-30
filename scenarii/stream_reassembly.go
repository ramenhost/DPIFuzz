package scenarii

import (
	// "bytes"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"sort"
	"strings"
	// "time"
)

//Scenario designed to specifically test server stream reassembly functionality. This scenario does not randomly insert stream data blocked and reset frames.
//For a more generalised case, refer to the generalised_stream_reassembly.
const (
	SR_TLSHandshakeFailed       = 1
	SR_HostDidNotRespond        = 2
	SR_EndpointDoesNotSupportHQ = 3
)

type StreamReassemblyScenario struct {
	AbstractScenario
}

func NewStreamReassemblyScenario() *StreamReassemblyScenario {
	return &StreamReassemblyScenario{AbstractScenario{name: "stream_reassembly", version: 2}}
}
func (s *StreamReassemblyScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {
	multiStream := true
	numStreams := 1
	var validStreams []uint64
	var usedStreams []uint64
	streamDataRecord := make(map[uint64]uint64)

	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = SR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	if multiStream {
		//add check to ensure that this number does not exceed that specified by transport parameters
		numStreams = R.Intn(40)
	}

	for i := 0; i <= numStreams; i += 4 {
		validStreams = append(validStreams, uint64(i))
	}

	numPackets := R.Intn(100)
	fmt.Println("Number of Stream:", numStreams)
	fmt.Println("Number of packets:", numPackets)
	var packetList []*ProtectedPacket

	//insertion packet example
	// payload_start := []byte(fmt.Sprintf("CIS"))
	// payload_end := []byte(fmt.Sprintf("PA"))
	// pp1 := NewProtectedPacket(conn)
	// pp1.Frames = append(pp1.Frames, NewStreamFrame(0, 0, payload_start, false))
	// pp2 := NewProtectedPacket(conn)
	// pp2.Frames = append(pp2.Frames, NewStreamFrame(44, 0, payload_end, false))
	// pp3 := NewProtectedPacket(conn)
	// pp3.Frames = append(pp2.Frames, NewStreamFrame(0, uint64(len(payload_start)), []byte{}, true))
	// pp4 := NewProtectedPacket(conn)
	// pp4.Frames = append(pp4.Frames, NewStreamFrame(44, uint64(len(payload_end)), []byte{}, true))
	// conn.DoSendPacket(pp4, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp2, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp3, EncryptionLevel1RTT)
	// conn.DoSendPacket(pp1, EncryptionLevel1RTT)

	for i := 0; i < numPackets; i++ {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		streamId := validStreams[uint64(R.Intn(len(validStreams)))]
		usedStreams = append(usedStreams, streamId)
		payloadLength := R.Intn(50)
		payload := RandStringBytes(payloadLength)
		//evasion packet example
		// if i == 6 {
		// 	payload = []byte("BigRisk")
		// }
		// if i == 7 {
		// 	payload = []byte("Payload")
		// }
		//payloadLength = len(payload)
		// fmt.Println("Packet Number:", i)
		// fmt.Println("Payload:", string(payload))
		// fmt.Println("Stream Id: ", streamId)
		// fmt.Println("-------------------------")
		streamDataRecord[streamId] += uint64(payloadLength)
		packetList[i].Frames = append(packetList[i].Frames, NewStreamFrame(streamId, streamDataRecord[streamId]-uint64(payloadLength), payload, false))
	}

	//TODO: Correct this. Iterate over map and not usedStreams. This will lead to repeated packets being created.
	for i, id := range usedStreams {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		packetList[i+numPackets].Frames = append(packetList[i+numPackets].Frames, NewStreamFrame(id, streamDataRecord[id], []byte{}, true))
	}

	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[i], packetList[i] })

	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	// <-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	for _, packet := range packetList {
		conn.DoSendPacketFuzz(packet, EncryptionLevel1RTT)
	}

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
					// streamData += string(stream.ReadData)
					// if res := bytes.Compare(stream.ReadData, payload1); res != 0 {
					// 	trace.ErrorCode = EC_PayloadChanged
					// 	fmt.Println("Not the same\n")
					// 	fmt.Println(string(stream.ReadData))
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
	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = SR_HostDidNotRespond
	}
}
