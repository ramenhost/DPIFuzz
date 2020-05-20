package mutators

import (
	. "github.com/QUIC-Tracker/quic-tracker"
)

func SequenceLevelMutations(packetList []*ProtectedPacket) []*ProtectedPacket {
	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[i], packetList[i] }) //Modified Shuffle
	// R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })//Standard Shuffle
	return packetList
}
