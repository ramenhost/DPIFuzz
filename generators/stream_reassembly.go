package generators

import (
	// "bytes"
	// "fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	// "sort"
	// "strings"
	// // "time"
)

func GenerateStreamReassembly(conn *Connection) []*ProtectedPacket {
	var packetList []*ProtectedPacket
	var validStreams []uint64
	var usedStreams []uint64
	streamDataRecord := make(map[uint64]uint64)

	numStreams := R.Intn(40)

	for i := 0; i <= numStreams; i += 4 {
		validStreams = append(validStreams, uint64(i))
	}

	numPackets := R.Intn(100)

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

	return packetList
}
