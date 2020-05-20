package generators

import (
	// "bytes"
	// "fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	// "sort"
	// "strings"
	// // "time"
)

func GenerateGeneralStreamReassembly(conn *Connection) []*ProtectedPacket {
	var validStreams []uint64
	var usedStreams []uint64
	streamDataRecord := make(map[uint64]uint64)
	numStreams := R.Intn(40)

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

	return packetList
}
