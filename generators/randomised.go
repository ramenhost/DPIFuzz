package generators

import (
	. "github.com/QUIC-Tracker/quic-tracker"
)

func Randomised(conn *Connection) []*ProtectedPacket {

	var list = [22]FrameType{PaddingFrameType, PingType, AckType, AckECNType, ResetStreamType, StopSendingType, CryptoType, NewTokenType, RetireConnectionIdType, PathChallengeType, PathResponseType, ConnectionCloseType, ApplicationCloseType, HandshakeDoneType}

	numProtectedPackets := R.Intn(20)
	var arr []FrameType
	for i := 0; i < numProtectedPackets; i++ {
		index := R.Intn(22)
		arr = append(arr, list[index])
	}
	var packetList []*ProtectedPacket
	for i := 0; i < numProtectedPackets; i++ {
		packetList = append(packetList, NewProtectedPacket(conn))
		switch c := arr[i]; c {
		case 0x00:
			paddingFrame := new(PaddingFrame)
			packetList[i].Frames = append(packetList[i].Frames, paddingFrame)
		case 0x01:
			pingFrame := new(PingFrame)
			packetList[i].Frames = append(packetList[i].Frames, pingFrame)
		case 0x02:
			ackFrame := new(AckFrame)
			ackFrame.LargestAcknowledged = PacketNumber(R.Intn(10))
			ackFrame.AckDelay = uint64(R.Intn(10))
			ackFrame.AckRangeCount = uint64(R.Intn(10))

			firstBlock := AckRange{}
			firstBlock.AckRange = uint64(R.Intn(10))
			ackFrame.AckRanges = append(ackFrame.AckRanges, firstBlock)

			var j uint64
			for j = 0; j < ackFrame.AckRangeCount; j++ {
				ack := AckRange{}
				ack.Gap = uint64(R.Intn(10))
				ack.AckRange = uint64(R.Intn(10))
				ackFrame.AckRanges = append(ackFrame.AckRanges, ack)
			}
			packetList[i].Frames = append(packetList[i].Frames, ackFrame)
		case 0x03:
			ackFrame := new(AckFrame)
			ackFrame.LargestAcknowledged = PacketNumber(R.Intn(10))
			ackFrame.AckDelay = uint64(R.Intn(10))
			ackFrame.AckRangeCount = uint64(R.Intn(10))

			firstBlock := AckRange{}
			firstBlock.AckRange = uint64(R.Intn(10))
			ackFrame.AckRanges = append(ackFrame.AckRanges, firstBlock)

			var j uint64
			for j = 0; j < ackFrame.AckRangeCount; j++ {
				ack := AckRange{}
				ack.Gap = uint64(R.Intn(10))
				ack.AckRange = uint64(R.Intn(10))
				ackFrame.AckRanges = append(ackFrame.AckRanges, ack)
			}
			frame := &AckECNFrame{*ackFrame, 0, 0, 0}

			frame.ECT0Count = uint64(R.Intn(10))
			frame.ECT1Count = uint64(R.Intn(10))
			frame.ECTCECount = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x04:
			resetFrame := new(ResetStream)
			resetFrame.StreamId = uint64(R.Intn(10))
			resetFrame.ApplicationErrorCode = uint64(R.Intn(10))
			resetFrame.FinalSize = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, resetFrame)
		case 0x05:
			frame := new(StopSendingFrame)
			frame.StreamId = uint64(R.Intn(10))
			frame.ApplicationErrorCode = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x06:
			frame := &CryptoFrame{Offset: uint64(R.Intn(10)), CryptoData: RandStringBytes(10), Length: uint64(R.Intn(10))}
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x07:
			frame := new(NewTokenFrame)
			tokenLength := uint64(R.Intn(10))
			frame.Token = make([]byte, tokenLength)
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x08:
			frame := NewStreamFrame(uint64(R.Intn(10)), uint64(R.Intn(10)), RandStringBytes(10), R.Float32() < 0.5)
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x10:
			frame := new(MaxDataFrame)
			frame.MaximumData = uint64(R.Intn(100))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x11:
			frame := new(MaxStreamDataFrame)
			frame.StreamId = uint64(R.Intn(10))
			frame.MaximumStreamData = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x12:
			frame := new(MaxStreamsFrame)
			frame.MaximumStreams = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x14:
			frame := new(DataBlockedFrame)
			frame.DataLimit = uint64(R.Intn(100))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x15:
			frame := new(StreamDataBlockedFrame)
			frame.StreamId = uint64(R.Intn(10))
			frame.StreamDataLimit = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x16:
			frame := new(StreamsBlockedFrame)
			frame.StreamLimit = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x18:
			frame := new(NewConnectionIdFrame)
			frame.Sequence = uint64(R.Intn(10))
			frame.RetirePriorTo = uint64(R.Intn(10))
			frame.Length = uint8(R.Intn(10))
			frame.ConnectionId = make([]byte, frame.Length, frame.Length)
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x19:
			frame := new(RetireConnectionId)
			frame.SequenceNumber = uint64(R.Intn(10))
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x1a:
			frame := new(PathChallenge)
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x1b:
			frame := new(PathResponse)
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x1c:
			frame := new(ConnectionCloseFrame)
			frame.ErrorCode = uint64(R.Intn(10))
			frame.ErrorFrameType = uint64(R.Intn(10))
			frame.ReasonPhraseLength = uint64(R.Intn(10))
			if frame.ReasonPhraseLength > 0 {
				reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
				frame.ReasonPhrase = string(reasonBytes)
			}
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x1d:
			frame := new(ApplicationCloseFrame)
			frame.ErrorCode = uint64(R.Intn(10))
			frame.ReasonPhraseLength = uint64(R.Intn(10))
			if frame.ReasonPhraseLength > 0 {
				reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
				frame.ReasonPhrase = string(reasonBytes)
			}
			packetList[i].Frames = append(packetList[i].Frames, frame)
		case 0x1e:
			frame := new(HandshakeDoneFrame)
			packetList[i].Frames = append(packetList[i].Frames, frame)
		}
	}
	return packetList
}
