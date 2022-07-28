//===- MCWinEH.h - Windows Unwinding Support --------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCWINEH_H
#define LLVM_MC_MCWINEH_H

#include "llvm/MC/MCStreamer.h"
#include <vector>

namespace llvm {

namespace WinEH {
  
struct Instruction {
  const MCSymbol *Label;
  const unsigned Offset;
  const unsigned Register;
  const unsigned Operation;

  Instruction(unsigned Op, MCSymbol *L, unsigned Reg, unsigned Off)
    : Label(L), Offset(Off), Register(Reg), Operation(Op) {}
};



class FrameInfo: public SEHFrameInfo {

public:
  MCStreamer &Streamer;
  SEHFrameInfo *ChainedParent = nullptr;
  const MCSymbol *ExceptionHandler = nullptr;
  const MCSymbol *PrologEnd = nullptr;
  const MCSection *TextSection = nullptr;

  bool HandlesUnwind = false;
  bool HandlesExceptions = false;

  int LastFrameInst = -1;
  std::vector<Instruction> Instructions;

  FrameInfo(MCStreamer *Streamer, SEHFrameInfo *ChainedParent)
    : Streamer(*Streamer), ChainedParent(ChainedParent) {}
  virtual ~FrameInfo();

  virtual void EmitWinCFIStartProc(const MCSymbol *Symbol,
                                   const class Function *F = nullptr,
                                   const StringRef Name = "",
                                   int32_t NArgs = -2, bool isSubroutine = false,
                                   bool isFunction = false) override;
  virtual void EmitWinCFIEndProc() override;
  virtual void EmitWinCFIStartChained() override;
  virtual SEHFrameInfo *EmitWinCFIEndChained() override;
  virtual void EmitWinCFIPushReg(unsigned Register, bool isFrameptr = false) override;
  virtual void EmitWinCFISetFrame(unsigned Register, unsigned Offset) override;
  virtual void EmitWinCFIAllocStack(unsigned Size) override;
  virtual void EmitWinCFISaveReg(unsigned Register, unsigned Offset) override;
  virtual void EmitWinCFISaveXMM(unsigned Register, unsigned Offset) override;
  virtual void EmitWinCFIPushFrame(bool Code) override;
  virtual void EmitWinCFIEndProlog() override;
  virtual void EmitWinCFIGotSaveOffset(unsigned Offset) override;
  virtual void EmitWinCFISaveBasePtr(unsigned Register, unsigned FrameOffset,
                                     unsigned FrameEndSize = 0) override;
  virtual void EmitWinCFIBeginEpilog() override;
  virtual void EmitWinCFIEndEpilog() override;

  virtual void EmitWinEHHandler(const MCSymbol *Sym, bool Unwind, bool Except) override;
  virtual void EmitWinEHHandlerData() override;

  virtual void EmitUnwindInfo() override;

  virtual bool isValidWinFrameInfo() override;
  virtual SEHFrameInfo *GetChainedParent() override;
  
private:
  void EmitLabel(MCSymbol *Symbol) { Streamer.EmitLabel(Symbol); }
  MCContext &getContext() const { return Streamer.getContext(); }
};

  
class UnwindEmitter: public SEHUnwindEmitter {
public:
  virtual ~UnwindEmitter();

  virtual SEHFrameInfo *createSEHFrameInfo(MCStreamer *Streamer,
                                           SEHFrameInfo *PrevFrame = nullptr) override;

  /// This emits the unwind info sections (.pdata and .xdata in PE/COFF).
  virtual void Emit(MCStreamer &Streamer) override;
 };
}
}

#endif
