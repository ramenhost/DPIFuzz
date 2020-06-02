package mutators

import (
	// "fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
)

func SequenceLevelMutations(packetList []*ProtectedPacket) []*ProtectedPacket {
	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[i], packetList[i] }) //Modified Shuffle(Shuffle+Drop+Duplicate)
	// // R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })//Standard Shuffle
	return packetList

	//In accordance with the paper
	// options := []Choice{{1, "no"}, {2, "yes"}}
	// //shuffle
	// val, err := WeightedChoice(options)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// if val.Item == "yes" {
	// 	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })
	// }
	// //duplicate
	// options = []Choice{{1, "no"}, {2, "yes"}}
	// val, err = WeightedChoice(options)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// if val.Item == "yes" {
	// 	var l []int
	// 	for i := 0; i < len(packetList); i++ {
	// 		if R.Float32() < 0.5 {
	// 			l = append(l, i)
	// 		}
	// 	}
	// 	for j := 0; j < len(l); j++ {
	// 		packetList = append(packetList, packetList[j])
	// 	}
	// 	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })
	// }
	// //drop
	// options = []Choice{{1, "no"}, {2, "yes"}}
	// val, err = WeightedChoice(options)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// count := 0
	// if val.Item == "yes" {
	// 	for i := 0; i < len(packetList); i++ {
	// 		if R.Float32() < 0.5 {
	// 			continue
	// 		} else {
	// 			packetList[count] = packetList[i]
	// 			count++
	// 		}
	// 	}
	// 	packetList = packetList[:count]
	// 	R.Shuffle(len(packetList), func(i, j int) { packetList[i], packetList[j] = packetList[j], packetList[i] })
	// }
	// return packetList
}
