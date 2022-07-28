//===-- MCAsmParserExtension.cpp - Asm Parser Hooks -----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCParser/MCAsmParserExtension.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCRegisterInfo.h"
using namespace llvm;

MCAsmParserExtension::MCAsmParserExtension() :
  BracketExpressionsSupported(false) {
}

MCAsmParserExtension::~MCAsmParserExtension() {
}

void MCAsmParserExtension::Initialize(MCAsmParser &Parser) {
  this->Parser = &Parser;

  // Win64 EH directives.
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveStartProc>(
                                                                 ".seh_proc");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveEndProc>(
                                                               ".seh_endproc");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveStartChained>(
                                                                    ".seh_startchained");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveEndChained>(
                                                                  ".seh_endchained");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveHandler>(
                                                               ".seh_handler");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveHandlerData>(
                                                                   ".seh_handlerdata");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectivePushReg>(
                                                               ".seh_pushreg");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveSetFrame>(
                                                                ".seh_setframe");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveAllocStack>(
                                                                  ".seh_stackalloc");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveSaveReg>(
                                                               ".seh_savereg");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveSaveXMM>(
                                                               ".seh_savexmm");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectivePushFrame>(
                                                                 ".seh_pushframe");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveEndProlog>(
                                                                 ".seh_endprologue");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveGotSaveOffset>(
                                                                         ".seh_gotsaveoffset");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveSaveBasePtr>(
                                                                   ".seh_savebaseptr");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveBeginEpilog>(
                                                                   ".seh_beginepilogue");
  addDirectiveHandler<&MCAsmParserExtension::ParseSEHDirectiveEndEpilog>(
                                                                 ".seh_endepilogue");
}

bool MCAsmParserExtension::ParseSEHDirectiveStartProc(StringRef, SMLoc) {
  StringRef SymbolID;
  StringRef Name = "";
  int64_t NArgs = -2;
  bool isSubroutine = false;
  bool isFunction = false;
  
  if (getParser().parseIdentifier(SymbolID))
    return true;
  
  while (!getLexer().isNot(AsmToken::EndOfStatement)) {
    if (getLexer().is(AsmToken::Comma)) {
      Lex();
      if (getLexer().isNot(AsmToken::At))
        return TokError("a start proc attribute must begin with '@'");

      SMLoc startLoc = getLexer().getLoc();
      Lex();
      
      StringRef identifier;
      if (getParser().parseIdentifier(identifier))
        return Error(startLoc, "Looking for @name=..., @num_args=#, @var_args, "
                     "@is_subroutine or @is_function");
      
      if (identifier == "name") {
        Lex();

        if (getLexer().isNot(AsmToken::Equal))
          return TokError("missing '='");
        Lex();

        if (getParser().parseIdentifier(Name))
          return true;
      }
      else if (identifier == "num_args") {
        Lex();
        
        if (getLexer().isNot(AsmToken::Equal))
          return TokError("missing '='");
        Lex();

        if (getParser().parseAbsoluteExpression(NArgs))
          return true;
      }
      else if (identifier == "var_args")
        NArgs = -1;
      else if (identifier == "is_subroutine")
        isSubroutine = true;
      else if (identifier == "is_function")
        isFunction = true;
      else
        return Error(startLoc, "Looking for @name=..., @num_args=#, @var_args, "
                     "@is_subroutine or @is_function");
      
      Lex();
      continue;
    }

    return TokError("unexpected token in directive");
  }
  MCSymbol *Symbol = getContext().getOrCreateSymbol(SymbolID);
  
  Lex();
  
  getStreamer().EmitWinCFIStartProc(Symbol, nullptr, Name, NArgs, isSubroutine, isFunction);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveEndProc(StringRef, SMLoc) {
  Lex();
  getStreamer().EmitWinCFIEndProc();
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveStartChained(StringRef, SMLoc) {
  Lex();
  getStreamer().EmitWinCFIStartChained();
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveEndChained(StringRef, SMLoc) {
  Lex();
  getStreamer().EmitWinCFIEndChained();
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveHandler(StringRef, SMLoc) {
  StringRef SymbolID;
  if (getParser().parseIdentifier(SymbolID))
    return true;
  
  if (getLexer().isNot(AsmToken::Comma))
    return TokError("you must specify one or both of @unwind or @except");
  Lex();
  bool unwind = false, except = false;
  if (ParseAtUnwindOrAtExcept(unwind, except))
    return true;
  if (getLexer().is(AsmToken::Comma)) {
    Lex();
    if (ParseAtUnwindOrAtExcept(unwind, except))
      return true;
  }
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  MCSymbol *handler = getContext().getOrCreateSymbol(SymbolID);
  
  Lex();
  getStreamer().EmitWinEHHandler(handler, unwind, except);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveHandlerData(StringRef, SMLoc) {
  Lex();
  getStreamer().EmitWinEHHandlerData();
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectivePushReg(StringRef, SMLoc L) {
  unsigned Reg = 0;
  bool fpFlag = false;
  if (ParseSEHRegisterNumber(Reg))
    return true;

  if (getLexer().is(AsmToken::Comma)) {
    Lex();
    if (getLexer().isNot(AsmToken::At))
      return TokError("Attributes must begin with '@'");
    Lex();
   if (getLexer().isNot(AsmToken::Identifier))
      return TokError("unexpected token in directive");
    if (getTok().getString() != "frameptr")
      return TokError("unexpected token in directive");
    fpFlag = true;
  }

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  Lex();
  getStreamer().EmitWinCFIPushReg(Reg, fpFlag);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveSetFrame(StringRef, SMLoc L) {
  unsigned Reg = 0;
  int64_t Off;
  if (ParseSEHRegisterNumber(Reg))
    return true;
  if (getLexer().isNot(AsmToken::Comma))
    return TokError("you must specify a stack pointer offset");
  
  Lex();
  SMLoc startLoc = getLexer().getLoc();
  if (getParser().parseAbsoluteExpression(Off))
    return true;
  
  if (Off & 0x0F)
    return Error(startLoc, "offset is not a multiple of 16");
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  Lex();
  getStreamer().EmitWinCFISetFrame(Reg, Off);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveAllocStack(StringRef, SMLoc) {
  int64_t Size;
  SMLoc startLoc = getLexer().getLoc();
  if (getParser().parseAbsoluteExpression(Size))
    return true;
  
  if (Size & 7)
    return Error(startLoc, "size is not a multiple of 8");
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  Lex();
  getStreamer().EmitWinCFIAllocStack(Size);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveSaveReg(StringRef, SMLoc L) {
  unsigned Reg = 0;
  int64_t Off;
  if (ParseSEHRegisterNumber(Reg))
    return true;
  if (getLexer().isNot(AsmToken::Comma))
    return TokError("you must specify an offset on the stack");
  
  Lex();
  SMLoc startLoc = getLexer().getLoc();
  if (getParser().parseAbsoluteExpression(Off))
    return true;
  
  if (Off & 7)
    return Error(startLoc, "size is not a multiple of 8");
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  Lex();
  // FIXME: Err on %xmm* registers
  getStreamer().EmitWinCFISaveReg(Reg, Off);
  return false;
}

// FIXME: This method is inherently x86-specific. It should really be in the
// x86 backend.
bool MCAsmParserExtension::ParseSEHDirectiveSaveXMM(StringRef, SMLoc L) {
  unsigned Reg = 0;
  int64_t Off;
  if (ParseSEHRegisterNumber(Reg))
    return true;
  if (getLexer().isNot(AsmToken::Comma))
    return TokError("you must specify an offset on the stack");
  
  Lex();
  SMLoc startLoc = getLexer().getLoc();
  if (getParser().parseAbsoluteExpression(Off))
    return true;
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  if (Off & 0x0F)
    return Error(startLoc, "offset is not a multiple of 16");
  
  Lex();
  // FIXME: Err on non-%xmm* registers
  getStreamer().EmitWinCFISaveXMM(Reg, Off);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectivePushFrame(StringRef, SMLoc) {
  bool Code = false;
  StringRef CodeID;
  if (getLexer().is(AsmToken::At)) {
    SMLoc startLoc = getLexer().getLoc();
    Lex();
    if (!getParser().parseIdentifier(CodeID)) {
      if (CodeID != "code")
        return Error(startLoc, "expected @code");
      Code = true;
    }
  }
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  Lex();
  getStreamer().EmitWinCFIPushFrame(Code);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveEndProlog(StringRef, SMLoc) {
  Lex();
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  getStreamer().EmitWinCFIEndProlog();
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveGotSaveOffset(StringRef, SMLoc) {
  Lex();
  int64_t Off;
  if (getParser().parseAbsoluteExpression(Off))
    return true;
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  getStreamer().EmitWinCFIGotSaveOffset(Off);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveSaveBasePtr(StringRef, SMLoc L) {
  unsigned Reg = 0;
  int64_t Off;
  if (ParseSEHRegisterNumber(Reg))
    return true;
  if (getLexer().isNot(AsmToken::Comma))
    return TokError("you must specify an offset on the stack");
  
  Lex();
  SMLoc startLoc = getLexer().getLoc();
  if (getParser().parseAbsoluteExpression(Off))
    return true;
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");
  
  if (Off & 0x0F)
    return Error(startLoc, "offset is not a multiple of 16");
  
  Lex();
  // FIXME: Err on non-%xmm* registers
  getStreamer().EmitWinCFISaveXMM(Reg, Off);
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveBeginEpilog(StringRef, SMLoc) {
  Lex();
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");

  getStreamer().EmitWinCFIBeginEpilog();
  return false;
}

bool MCAsmParserExtension::ParseSEHDirectiveEndEpilog(StringRef, SMLoc) {
  Lex();
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in directive");

  getStreamer().EmitWinCFIEndEpilog();
  return false;
}

bool MCAsmParserExtension::ParseAtUnwindOrAtExcept(bool &unwind, bool &except) {
  StringRef identifier;
  if (getLexer().isNot(AsmToken::At))
    return TokError("a handler attribute must begin with '@'");
  SMLoc startLoc = getLexer().getLoc();
  Lex();
  if (getParser().parseIdentifier(identifier))
    return Error(startLoc, "expected @unwind or @except");
  if (identifier == "unwind")
    unwind = true;
  else if (identifier == "except")
    except = true;
  else
    return Error(startLoc, "expected @unwind or @except");
  return false;
}

bool MCAsmParserExtension::ParseSEHRegisterNumber(unsigned &RegNo) {
  SMLoc startLoc = getLexer().getLoc();
  if (getLexer().is(AsmToken::Percent)) {
    const MCRegisterInfo *MRI = getContext().getRegisterInfo();
    SMLoc endLoc;
    unsigned LLVMRegNo;
    if (getParser().getTargetParser().ParseRegister(LLVMRegNo,startLoc,endLoc))
      return true;
    
#if 0
    // FIXME: TargetAsmInfo::getCalleeSavedRegs() commits a serious layering
    // violation so this validation code is disabled.
    
    // Check that this is a non-volatile register.
    const unsigned *NVRegs = TAI.getCalleeSavedRegs();
    unsigned i;
    for (i = 0; NVRegs[i] != 0; ++i)
      if (NVRegs[i] == LLVMRegNo)
        break;
    if (NVRegs[i] == 0)
      return Error(startLoc, "expected non-volatile register");
#endif
    
    int SEHRegNo = MRI->getSEHRegNum(LLVMRegNo);
    if (SEHRegNo < 0)
      return Error(startLoc,"register can't be represented in SEH unwind info");
    RegNo = SEHRegNo;
  }
  else {
    int64_t n;
    if (getParser().parseAbsoluteExpression(n))
      return true;
    if (n > 15)
      return Error(startLoc, "register number is too high");
    RegNo = n;
  }
  
  return false;
}
