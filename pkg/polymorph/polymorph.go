package polymorph

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

type Engine struct {
	seed       uint64
	transforms []Transform
	history    []Mutation
}

type Mutation struct {
	Timestamp  time.Time
	Seed       uint64
	Hash       [32]byte
	Transforms []string
}

type Transform interface {
	Name() string
	Apply(prog *Program, seed uint64) error
}

type Program struct {
	Instructions []Instruction
	Maps         []MapDef
	License      string
	Name         string
}

type Instruction struct {
	OpCode  uint8
	DstReg  uint8
	SrcReg  uint8
	Offset  int16
	Imm     int32
	Comment string
}

type MapDef struct {
	Name      string
	Type      uint32
	KeySize   uint32
	ValueSize uint32
	MaxEntries uint32
}

func NewEngine(seed uint64) *Engine {
	if seed == 0 {
		seed = uint64(time.Now().UnixNano())
	}
	e := &Engine{
		seed: seed,
		transforms: []Transform{
			&NOPInsertion{},
			&RegisterRename{},
			&ConstantObfuscation{},
			&DeadCodeInsertion{},
			&InstructionReorder{},
		},
	}
	return e
}

func (e *Engine) Mutate(prog *Program) (*Program, error) {
	if prog == nil {
		return nil, fmt.Errorf("nil program")
	}
	if len(prog.Instructions) == 0 {
		return nil, fmt.Errorf("empty program")
	}

	mutated := &Program{
		Instructions: make([]Instruction, len(prog.Instructions)),
		Maps:         prog.Maps,
		License:      prog.License,
		Name:         prog.Name,
	}
	copy(mutated.Instructions, prog.Instructions)

	e.seed = nextSeed(e.seed)

	var applied []string
	for _, t := range e.transforms {
		if err := t.Apply(mutated, e.seed); err != nil {
			continue
		}
		applied = append(applied, t.Name())
		e.seed = nextSeed(e.seed)
	}

	hash := hashProgram(mutated)
	e.history = append(e.history, Mutation{
		Timestamp:  time.Now(),
		Seed:       e.seed,
		Hash:       hash,
		Transforms: applied,
	})

	return mutated, nil
}

func (e *Engine) History() []Mutation {
	return e.history
}

func (e *Engine) SetTransforms(transforms []Transform) {
	e.transforms = transforms
}

func hashProgram(prog *Program) [32]byte {
	h := sha256.New()
	for _, inst := range prog.Instructions {
		b := make([]byte, 8)
		b[0] = inst.OpCode
		b[1] = (inst.DstReg & 0xF) | ((inst.SrcReg & 0xF) << 4)
		binary.LittleEndian.PutUint16(b[2:4], uint16(inst.Offset))
		binary.LittleEndian.PutUint32(b[4:8], uint32(inst.Imm))
		h.Write(b)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func nextSeed(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
}
