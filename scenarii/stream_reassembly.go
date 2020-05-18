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

	connAgents := s.CompleteHandshake(conn, trace, SR_TLSHandshakeFailed)
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

	var packetList []*ProtectedPacket

	for i := 0; i < numPackets; i++ {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		streamId := validStreams[uint64(R.Intn(len(validStreams)))]
		usedStreams = append(usedStreams, streamId)
		payloadLength := R.Intn(50)
		payload := RandStringBytes(payloadLength)
		streamDataRecord[streamId] += uint64(payloadLength)
		packetList[i].Frames = append(packetList[i].Frames, NewStreamFrame(streamId, streamDataRecord[streamId]-uint64(payloadLength), payload, false))
	}

	//TODO: Correct this. Iterate over map and not usedStreams. This will lead to repeated packets being created.
	for i, id := range usedStreams {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		packetList[i+numPackets].Frames = append(packetList[i+numPackets].Frames, NewStreamFrame(id, streamDataRecord[id], RandStringBytes(R.Intn(10)), true))
		// packetList[i+numPackets].Frames = append(packetList[i+numPackets].Frames, NewStreamFrame(id, streamDataRecord[id], []byte{}, true))
	}

	// R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[i], packetList[i] })
	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })

	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	// <-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	for _, packet := range packetList {
		for _, f := range packet.Frames {
			s := f.(*StreamFrame)
			fmt.Println("Testing:", s.StreamId, " FinBit:", s.FinBit, "Payload: ", string(s.StreamData), "Offset: ", s.Offset)
		}
	}

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
