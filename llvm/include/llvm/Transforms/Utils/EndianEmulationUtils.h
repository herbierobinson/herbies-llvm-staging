//===--- llvm/Transforms/Utils/EndianEmulationUtils.h - ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines some utility routines that code generation can use to determine
// when endian emulation requires byte swapping.
// See EndianEmulation.cpp.

#ifndef LLVM_TRANSFORMS_UTILS_ENDIAN_EMULATION_UTILS_H
#define LLVM_TRANSFORMS_UTILS_ENDIAN_EMULATION_UTILS_H


namespace llvm {

enum Endianness
  {
  AnyEndianness = -1,
  ProgramEndian = 0, // Zero for the default.
  BigEndian,
  LittleEndian,
  NativeEndian
};

void GenerateFullBswap(const class DataLayout *TD, class Instruction *IN,
                       class Value* arg, bool insertBefore,
                       class Instruction *&p_user,
                       class Instruction *&p_result);
  
class CallInst *getBswapInstruction(class Module *m, class Value *op);
  
Endianness ComputeEndianAccessType(const class Value *V, class Type *t,
                                   Endianness apiEndianess,
                                   Endianness targetEndianess);
}
#endif
