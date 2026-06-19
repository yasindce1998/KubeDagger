package polymorph

type NOPInsertion struct{}

func (t *NOPInsertion) Name() string { return "nop_insertion" }

func (t *NOPInsertion) Apply(prog *Program, seed uint64) error {
	var result []Instruction
	for i, inst := range prog.Instructions {
		result = append(result, inst)
		if seed%(uint64(i)+3) == 0 && inst.OpCode != BPFExit && !IsJump(inst) {
			nop := selectNOP(seed ^ uint64(i))
			result = append(result, nop)
		}
	}
	fixJumpOffsets(prog.Instructions, result)
	prog.Instructions = result
	return nil
}

func selectNOP(seed uint64) Instruction {
	switch seed % 4 {
	case 0:
		return MovReg(BPFRegR0, BPFRegR0)
	case 1:
		return XorImm(BPFRegR9, 0)
	case 2:
		return AddImm(BPFRegR8, 0)
	default:
		return Instruction{OpCode: BPFMovImm, DstReg: BPFRegR9, Imm: int32(seed & 0xFF)}
	}
}

type RegisterRename struct{}

func (t *RegisterRename) Name() string { return "register_rename" }

func (t *RegisterRename) Apply(prog *Program, seed uint64) error {
	scratchRegs := []uint8{BPFRegR6, BPFRegR7, BPFRegR8, BPFRegR9}

	mapping := make(map[uint8]uint8)
	perm := permuteRegisters(scratchRegs, seed)
	for i, orig := range scratchRegs {
		mapping[orig] = perm[i]
	}

	for i := range prog.Instructions {
		inst := &prog.Instructions[i]
		if newReg, ok := mapping[inst.DstReg]; ok && UsesDstReg(*inst) {
			inst.DstReg = newReg
		}
		if newReg, ok := mapping[inst.SrcReg]; ok && UsesSrcReg(*inst) {
			inst.SrcReg = newReg
		}
	}
	return nil
}

func permuteRegisters(regs []uint8, seed uint64) []uint8 {
	result := make([]uint8, len(regs))
	copy(result, regs)
	for i := len(result) - 1; i > 0; i-- {
		j := int(seed % uint64(i+1))
		seed = nextSeed(seed)
		result[i], result[j] = result[j], result[i]
	}
	return result
}

type ConstantObfuscation struct{}

func (t *ConstantObfuscation) Name() string { return "constant_obfuscation" }

func (t *ConstantObfuscation) Apply(prog *Program, seed uint64) error {
	var result []Instruction
	for _, inst := range prog.Instructions {
		if inst.OpCode == BPFMovImm && inst.Imm != 0 {
			xorKey := int32(seed & 0xFFFF)
			if xorKey == 0 {
				xorKey = 0x5A5A
			}
			obfuscated := inst.Imm ^ xorKey
			result = append(result, MovImm(inst.DstReg, obfuscated))
			result = append(result, XorImm(inst.DstReg, xorKey))
			seed = nextSeed(seed)
		} else {
			result = append(result, inst)
		}
	}
	fixJumpOffsets(prog.Instructions, result)
	prog.Instructions = result
	return nil
}

type DeadCodeInsertion struct{}

func (t *DeadCodeInsertion) Name() string { return "dead_code_insertion" }

func (t *DeadCodeInsertion) Apply(prog *Program, seed uint64) error {
	var result []Instruction
	for i, inst := range prog.Instructions {
		if seed%(uint64(i)+5) == 0 && !IsJump(inst) && inst.OpCode != BPFExit {
			deadLen := int16(2 + seed%3)
			result = append(result, JumpAlways(deadLen))
			for range int(deadLen) {
				result = append(result, MovImm(BPFRegR9, int32(seed&0xFF)))
				seed = nextSeed(seed)
			}
		}
		result = append(result, inst)
	}
	prog.Instructions = result
	return nil
}

type InstructionReorder struct{}

func (t *InstructionReorder) Name() string { return "instruction_reorder" }

func (t *InstructionReorder) Apply(prog *Program, seed uint64) error {
	for i := 0; i+1 < len(prog.Instructions); i++ {
		a := prog.Instructions[i]
		b := prog.Instructions[i+1]

		if IsJump(a) || IsJump(b) || a.OpCode == BPFExit || b.OpCode == BPFExit || a.OpCode == BPFCall || b.OpCode == BPFCall {
			continue
		}

		if !hasDataDependency(a, b) && seed%(uint64(i)+7) == 0 {
			prog.Instructions[i] = b
			prog.Instructions[i+1] = a
			seed = nextSeed(seed)
			i++
		}
	}
	return nil
}

func hasDataDependency(a, b Instruction) bool {
	if UsesDstReg(a) {
		if UsesSrcReg(b) && b.SrcReg == a.DstReg {
			return true
		}
		if UsesDstReg(b) && b.DstReg == a.DstReg {
			return true
		}
	}
	return false
}

func fixJumpOffsets(original, expanded []Instruction) {
	if len(original) == 0 {
		return
	}

	posMap := make(map[int]int)
	origIdx := 0
	for expIdx := range expanded {
		if origIdx < len(original) && expanded[expIdx].OpCode == original[origIdx].OpCode &&
			expanded[expIdx].DstReg == original[origIdx].DstReg {
			posMap[origIdx] = expIdx
			origIdx++
		}
	}

	for i := range expanded {
		if IsJump(expanded[i]) && expanded[i].OpCode != BPFJA {
			oldTarget := i + int(expanded[i].Offset) + 1
			if oldTarget < len(expanded) {
				continue
			}
		}
	}
}
