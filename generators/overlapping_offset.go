package generators

import (
	// "bytes"
	// "fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	// "sort"
	// "strings"
	// // "time"
)

func GenerateOverlappingOffset(conn *Connection) []*ProtectedPacket {
	var validStreams []uint64

	//add check to ensure that this number does not exceed that specified by transport parameters
	numStreams := R.Intn(1)

	for i := 0; i <= numStreams; i += 4 {
		validStreams = append(validStreams, uint64(i))
	}

	numFragments := R.Intn(3-1) + 1

	var packetList []*ProtectedPacket

	count := 0

	for _, id := range validStreams {
		dataLength := R.Intn(20-10) + 10
		for i := 0; i < numFragments; i++ {
			temp := 0
			for temp < dataLength {
				payloadLength := R.Intn(10)
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

	return packetList
}
