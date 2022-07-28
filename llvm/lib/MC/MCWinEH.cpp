//===- lib/MC/MCWinEH.cpp - Windows EH implementation ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCSectionCOFF.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCWinEH.h"
#include "llvm/MC/MCWin64EH.h"
#include "llvm/Support/COFF.h"

namespace llvm {
namespace WinEH {

FrameInfo::~FrameInfo() {}

void FrameInfo::EmitWinCFIStartProc(const MCSymbol *Symbol,
                                     const class Function *F, StringRef Name,
                                     int32_t NArg, bool isSubroutine,
                                     bool isFunction) {
  
  MCSymbol *StartProc = Streamer.EmitCFILabel();
  Begin = StartProc;
  
  TextSection = Streamer.getCurrentSectionOnly();
}

void FrameInfo::EmitWinCFIEndProc() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  End = Label;
}

void FrameInfo::EmitWinCFIStartChained() {
  MCSymbol *StartProc = Streamer.EmitCFILabel();
  Begin = StartProc;

  TextSection = Streamer.getCurrentSectionOnly();
}

SEHFrameInfo * FrameInfo::EmitWinCFIEndChained() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  End = Label;
  return ChainedParent;
}

void FrameInfo::EmitWinCFIPushReg(unsigned Register, bool isFrameptr) {
  MCSymbol *Label = Streamer.EmitCFILabel();

  Instruction Inst = Win64EH::Instruction::PushNonVol(Label, Register, isFrameptr);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFISetFrame(unsigned Register, unsigned Offset) {
  if (LastFrameInst >= 0)
    report_fatal_error("Frame register and offset already specified!");
  if (Offset & 0x0F)
    report_fatal_error("Misaligned frame pointer offset!");
  if (Offset > 240)
    report_fatal_error("Frame offset must be less than or equal to 240!");
  
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst =
          Win64EH::Instruction::SetFPReg(Label, Register, Offset);
  LastFrameInst = Instructions.size();
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFIAllocStack(unsigned Size) {
  if (Size == 0)
    report_fatal_error("Allocation size must be non-zero!");
  if (Size & 7)
    report_fatal_error("Misaligned stack allocation!");
  
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst = Win64EH::Instruction::Alloc(Label, Size);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFISaveReg(unsigned Register, unsigned Offset) {
   if (Offset & 7)
    report_fatal_error("Misaligned saved register offset!");
  
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst =
  Win64EH::Instruction::SaveNonVol(Label, Register, Offset);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFISaveXMM(unsigned Register, unsigned Offset) {
  if (Offset & 0x0F)
    report_fatal_error("Misaligned saved vector register offset!");
  
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst =
  Win64EH::Instruction::SaveXMM(Label, Register, Offset);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFIPushFrame(bool Code) {
  if (Instructions.size() > 0)
    report_fatal_error("If present, PushMachFrame must be the first UOP");
  
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst = Win64EH::Instruction::PushMachFrame(Label, Code);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFIEndProlog() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  PrologEnd = Label;
}

void FrameInfo::EmitWinCFIGotSaveOffset(unsigned Offset) {
}

void FrameInfo::EmitWinCFISaveBasePtr(unsigned Register, unsigned FrameOffset,
                                       unsigned FrameEndSize) {
  if (FrameOffset & 0x03)
    report_fatal_error("Misaligned saved base pointer register offset!");
  
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst =
  Win64EH::Instruction::SaveBasePtr(Label, Register, FrameOffset);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFIBeginEpilog() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst = Win64EH::Instruction::BeginEpilog(Label);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinCFIEndEpilog() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  Instruction Inst = Win64EH::Instruction::EndEpilog(Label);
  Instructions.push_back(Inst);
}

void FrameInfo::EmitWinEHHandler(const MCSymbol *Sym, bool Unwind,
                                  bool Except) {
  ExceptionHandler = Sym;
  if (Unwind)
    HandlesUnwind = true;
  if (Except)
    HandlesExceptions = true;
}

void FrameInfo::EmitWinEHHandlerData() {
  if (ChainedParent)
    report_fatal_error("Chained unwind areas can't have handlers!");

  // Switch sections. Don't call SwitchSection directly, because that will
  // cause the section switch to be visible in the emitted assembly.
  // We only do this so the section switch that terminates the handler
  // data block is visible.
  MCSection *TextSec = &Function->getSection();
  MCSection *XData = Streamer.getAssociatedXDataSection(TextSec);
  Streamer.SwitchSectionNoChange(XData);
  
}

bool FrameInfo::isValidWinFrameInfo()
{
  return !End;
}
SEHFrameInfo *FrameInfo::GetChainedParent()
{
  return ChainedParent;
}


UnwindEmitter::~UnwindEmitter() {}

SEHFrameInfo *UnwindEmitter::createSEHFrameInfo(MCStreamer *Streamer,
                                         SEHFrameInfo *ChainedParent)
{
  return new FrameInfo(Streamer, ChainedParent);
}

void UnwindEmitter::Emit(MCStreamer &Streamer)
{
}

}
}

