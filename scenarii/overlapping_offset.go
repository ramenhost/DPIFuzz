package scenarii

import (
	// "bytes"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"sort"
	"strings"
	// "time"
)

//Scenario designed to specifically test server handling of overlapping offsets

type OverlappingOffsetScenario struct {
	AbstractScenario
}

func NewOverlappingOffsetScenario() *OverlappingOffsetScenario {
	return &OverlappingOffsetScenario{AbstractScenario{name: "overlapping_offset", version: 2}}
}
func (s *OverlappingOffsetScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {

	var validStreams []uint64

	if !strings.Contains(conn.ALPN, "hq") && !strings.Contains(conn.ALPN, "h3") {
		trace.ErrorCode = SR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	//add check to ensure that this number does not exceed that specified by transport parameters
	numStreams := R.Intn(10)

	for i := 0; i <= numStreams; i += 4 {
		validStreams = append(validStreams, uint64(i))
	}

	numFragments := R.Intn(3-1) + 1
	fmt.Println("Number of Stream:", numStreams)
	fmt.Println("Number of fragments:", numFragments)
	var packetList []*ProtectedPacket

	count := 0

	for _, id := range validStreams {
		dataLength := R.Intn(30-10) + 10
		for i := 0; i < numFragments; i++ {
			temp := 0
			for temp < dataLength {
				payloadLength := R.Intn(5-1) + 1
				payload := RandStringBytes(payloadLength)
				streamPacket := NewProtectedPacket(conn)
				packetList = append(packetList, streamPacket)
				packetList[count].Frames = append(packetList[count].Frames, NewStreamFrame(id, uint64(temp), payload, false))
				count = count + 1
				temp = temp + payloadLength
			}
			packet := NewProtectedPacket(conn)
			packetList = append(packetList, packet)
			packetList[count].Frames = append(packetList[count].Frames, NewStreamFrame(id, uint64(temp), RandStringBytes(R.Intn(10)), true))
			count = count + 1
		}

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
