package scenarii

import (
	// "bytes"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"sort"
	"strings"
	"time"
)

//Scenario designed to test server stream reassembly functionality.
//Here, we randomly send three types of frames i.e. Stream Frames, Reset Stream Frame,
//Stream Data Blocked Frame.

type GeneralStreamReassemblyScenario struct {
	AbstractScenario
}

func NewGeneralStreamReassemblyScenario() *GeneralStreamReassemblyScenario {
	return &GeneralStreamReassemblyScenario{AbstractScenario{name: "general_stream_reassembly", version: 2}}
}
func (s *GeneralStreamReassemblyScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {
	multiStream := true
	numStreams := 1

	//should we use only valid stream numbers or fuzz those as well ? Using valid for now as it seems
	//both DPI and server should easily be able to discard invalid stream numbers.

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

	numStreamPackets := R.Intn(100)
	numResetPackets := R.Intn(25)
	numBlockedPackets := R.Intn(25)
	var packetList []*ProtectedPacket

	//generating stream frames
	for i := 0; i < numStreamPackets; i++ {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		streamId := validStreams[uint64(R.Intn(len(validStreams)))]
		usedStreams = append(usedStreams, streamId)
		payloadLength := R.Intn(50)
		payload := RandStringBytes(payloadLength)
		streamDataRecord[streamId] += uint64(payloadLength)
		packetList[i].Frames = append(packetList[i].Frames, NewStreamFrame(streamId, streamDataRecord[streamId]-uint64(payloadLength), payload, false))
	}

	//generating stream reset frames
	for i := numStreamPackets; i < numResetPackets+numStreamPackets; i++ {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		resetFrame := new(ResetStream)
		resetFrame.StreamId = uint64(R.Intn(10) * 4)
		resetFrame.ApplicationErrorCode = uint64(R.Intn(5))
		resetFrame.FinalSize = uint64(R.Intn(50)) //not sure whether this should be random or should we put the actual value.
		packetList[i].Frames = append(packetList[i].Frames, resetFrame)

	}

	//generating stream blocked frames
	for i := numStreamPackets + numResetPackets; i < numStreamPackets+numResetPackets+numBlockedPackets; i++ {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		blockFrame := new(StreamDataBlockedFrame)
		blockFrame.StreamId = uint64(R.Intn(10) * 4)
		blockFrame.StreamDataLimit = uint64(R.Intn(50))
		packetList[i].Frames = append(packetList[i].Frames, blockFrame)
	}

	//generating stream close frames
	for i, id := range usedStreams {
		packet := NewProtectedPacket(conn)
		packetList = append(packetList, packet)
		packetList[i+numStreamPackets+numResetPackets+numBlockedPackets].Frames = append(packetList[i+numStreamPackets+numResetPackets+numBlockedPackets].Frames, NewStreamFrame(id, streamDataRecord[id], []byte{}, true))
	}

	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[i], packetList[i] })
	// R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })

	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

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
					streamData += string(stream.ReadData)
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
