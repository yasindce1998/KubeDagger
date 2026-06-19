package polymorph

const (
	BPFClassLD   = 0x00
	BPFClassLDX  = 0x01
	BPFClassST   = 0x02
	BPFClassSTX  = 0x03
	BPFClassALU  = 0x04
	BPFClassJMP  = 0x05
	BPFClassALU64 = 0x07

	BPFMovImm  = 0xb7
	BPFMovReg  = 0xbf
	BPFAddImm  = 0x07
	BPFAddReg  = 0x0f
	BPFSubImm  = 0x17
	BPFSubReg  = 0x1f
	BPFXorImm  = 0xa7
	BPFXorReg  = 0xaf
	BPFJA      = 0x05
	BPFExit    = 0x95
	BPFCall    = 0x85

	BPFRegR0  = 0
	BPFRegR1  = 1
	BPFRegR2  = 2
	BPFRegR3  = 3
	BPFRegR4  = 4
	BPFRegR5  = 5
	BPFRegR6  = 6
	BPFRegR7  = 7
	BPFRegR8  = 8
	BPFRegR9  = 9
	BPFRegR10 = 10
)

func MovImm(dst uint8, imm int32) Instruction {
	return Instruction{OpCode: BPFMovImm, DstReg: dst, Imm: imm}
}

func MovReg(dst, src uint8) Instruction {
	return Instruction{OpCode: BPFMovReg, DstReg: dst, SrcReg: src}
}

func AddImm(dst uint8, imm int32) Instruction {
	return Instruction{OpCode: BPFAddImm, DstReg: dst, Imm: imm}
}

func XorImm(dst uint8, imm int32) Instruction {
	return Instruction{OpCode: BPFXorImm, DstReg: dst, Imm: imm}
}

func JumpAlways(offset int16) Instruction {
	return Instruction{OpCode: BPFJA, Offset: offset}
}

func Exit() Instruction {
	return Instruction{OpCode: BPFExit}
}

func IsALU(inst Instruction) bool {
	class := inst.OpCode & 0x07
	return class == BPFClassALU || class == BPFClassALU64
}

func IsJump(inst Instruction) bool {
	class := inst.OpCode & 0x07
	return class == BPFClassJMP
}

func IsLoad(inst Instruction) bool {
	class := inst.OpCode & 0x07
	return class == BPFClassLD || class == BPFClassLDX
}

func IsStore(inst Instruction) bool {
	class := inst.OpCode & 0x07
	return class == BPFClassST || class == BPFClassSTX
}

func UsesDstReg(inst Instruction) bool {
	return IsALU(inst) || IsLoad(inst) || inst.OpCode == BPFMovImm || inst.OpCode == BPFMovReg
}

func UsesSrcReg(inst Instruction) bool {
	return (inst.OpCode&0x08) != 0 && (IsALU(inst) || IsStore(inst) || inst.OpCode == BPFMovReg)
}

func ParseELFInstructions(raw []byte) []Instruction {
	if len(raw)%8 != 0 {
		return nil
	}
	var insns []Instruction
	for i := 0; i+8 <= len(raw); i += 8 {
		inst := Instruction{
			OpCode: raw[i],
			DstReg: raw[i+1] & 0x0F,
			SrcReg: (raw[i+1] >> 4) & 0x0F,
			Offset: int16(uint16(raw[i+2]) | uint16(raw[i+3])<<8),
			Imm:    int32(uint32(raw[i+4]) | uint32(raw[i+5])<<8 | uint32(raw[i+6])<<16 | uint32(raw[i+7])<<24),
		}
		insns = append(insns, inst)
	}
	return insns
}

func EncodeInstructions(insns []Instruction) []byte {
	raw := make([]byte, len(insns)*8)
	for i, inst := range insns {
		off := i * 8
		raw[off] = inst.OpCode
		raw[off+1] = (inst.DstReg & 0x0F) | ((inst.SrcReg & 0x0F) << 4)
		raw[off+2] = byte(uint16(inst.Offset))
		raw[off+3] = byte(uint16(inst.Offset) >> 8)
		raw[off+4] = byte(uint32(inst.Imm))
		raw[off+5] = byte(uint32(inst.Imm) >> 8)
		raw[off+6] = byte(uint32(inst.Imm) >> 16)
		raw[off+7] = byte(uint32(inst.Imm) >> 24)
	}
	return raw
}
