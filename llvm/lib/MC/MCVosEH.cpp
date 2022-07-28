//===- lib/MC/MCVosEH.cpp - MCVosEH implementation --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCVosEH.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCSectionCOFF.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/Win64EH.h"
#include "llvm/Support/ELF.h"

using namespace llvm;
VosEHFrameInfo::~VosEHFrameInfo() {}

VosEHFrameInfo::VosEHFrameInfo(MCStreamer *Streamer,
                               VosEHUnwindEmitter *UnwindEmitter,
                               SEHFrameInfo *ChainedParent) : Streamer(*Streamer), UnwindEmitter(*UnwindEmitter), ChainedParent(ChainedParent) {

  Symbol = getContext().createTempSymbol();
  FunctionName = "";

  memset(&e, 0, sizeof(e));
  e.symtab_addr = 1;
  e.block_node_addr = 1;
  e.reg_save_area_offset = 4;
  e.n_args = -2;
}

void VosEHFrameInfo::EmitWinCFIStartProc(const MCSymbol *Symbol,
                                    const class Function *F, StringRef Name,
                                    int32_t NArg, bool isSubroutine,
                                    bool isFunction) {
  Function = Symbol;
  MCSymbol *StartProc = Streamer.EmitCFILabel();
  Begin = StartProc;
  //  TextSection = Streamer.getCurrentSectionOnly();
  FunctionName = Name;
  e.name.len = FunctionName.size();
  e.n_args = NArg;
  if (isSubroutine)
    e.flags |= entry_block_ia32_flags_is_subroutine;
  if (isFunction)
    e.flags |= entry_block_ia32_flags_is_function;

  BlockMapItem PB = BlockMapItem(Prolog, StartProc, Symbol);
  UnwindEmitter.InsertBlockMapItem(PB);
}

void VosEHFrameInfo::EmitWinCFIEndProc() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  End = Label;

  BlockMapItem EB = BlockMapItem(EndOfCode, Label);
  UnwindEmitter.InsertBlockMapItem(EB);
}

void VosEHFrameInfo::EmitWinCFIStartChained() {
  MCSymbol *StartProc = Streamer.EmitCFILabel();
  Begin = StartProc;
  //  TextSection = Streamer.getCurrentSectionOnly();
  BlockMapItem PB = BlockMapItem(Prolog, StartProc, Symbol);
  UnwindEmitter.InsertBlockMapItem(PB);
}

SEHFrameInfo * VosEHFrameInfo::EmitWinCFIEndChained() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  End = Label;
  BlockMapItem EB = BlockMapItem(EndOfCode, Label);
  UnwindEmitter.InsertBlockMapItem(EB);
  return ChainedParent;
}

void VosEHFrameInfo::EmitWinCFIPushReg(unsigned Register, bool isFrameptr) {
  entryOpProcessed = true;
  if (Register == regEnconding::EBP) {
    if(e.flags2.ebp_saved || e.flags2.fp_in_reg)
      report_fatal_error("EBP saved more than once in the same prolog!");
    if (regsPushed > 0 || frameUpdated)
      report_fatal_error("ebp must be pushed first on VOS!");
    e.flags2.ebp_saved = true;
    e.reg_save_area_offset = 0;
    if (isFrameptr)
      e.flags2.fp_in_reg = true;
  }
  else {
    if (frameUpdated)
      registerPushedAfterFrame = true;
    else
      registerPushedBeforeFrame = true;
    
    switch(Register) {
      case regEnconding::EBX:
        if (e.flags2.ebx_saved)
          report_fatal_error("EBX saved more than once in the same prolog!");
        regsPushed++;
        e.flags2.ebx_saved = regsPushed;
        break;
      case regEnconding::ESI:
        if (e.flags2.esi_saved)
          report_fatal_error("ESI saved more than once in the same prolog!");
        regsPushed++;
        e.flags2.esi_saved = regsPushed;
        break;
      case regEnconding::EDI:
        if (e.flags2.edi_saved)
          report_fatal_error("EDI saved more than once in the same prolog!");
        regsPushed++;
        e.flags2.edi_saved = regsPushed;
        break;
      default:
        report_fatal_error("VOS only supports saving EBP, EBX, ESI and EDI!");
    }
  }
}

void VosEHFrameInfo::EmitWinCFISetFrame(unsigned Register, unsigned Offset) {
  entryOpProcessed = true;
  if (e.flags2.fap_offset_is_SEHFrameOffset)
    report_fatal_error("Frame register and offset already specified!");

  // Need to research what this is:  The limits may be larger...
  if (Offset & 0x0F)
    report_fatal_error("Misaligned frame pointer offset!");
  if (Offset > 240)
    report_fatal_error("Frame offset must be less than or equal to 240!");
  
  e.flags2.fap_offset_is_SEHFrameOffset = true;
  e.fap_offset = Offset;
}

void VosEHFrameInfo::EmitWinCFIAllocStack(unsigned Size) {
  entryOpProcessed = true;
  if (Size == 0)
    report_fatal_error("Allocation size must be non-zero!");
  if (Size & 0xf)
    report_fatal_error("Misaligned stack allocation!");
  if (frameUpdated)
    report_fatal_error("Frame size already specified!");

  e.frame_size = Size - 4;
  frameUpdated = true;
}

void VosEHFrameInfo::EmitWinCFISaveReg(unsigned Register, unsigned Offset) {
  entryOpProcessed = true;

  if (Offset & 3)
    report_fatal_error("Misaligned saved register offset!");

  if (Register == regEnconding::EBP) {
    if(e.flags2.ebp_saved || e.flags2.fp_in_reg)
      report_fatal_error("EBP saved more than once in the same prolog!");
    ebpSaveOffset = Offset;
    e.flags2.ebp_saved = true;
  }
  else {
    assert(regsPushed == 0);
    if (!registerSaved || Offset > highestSaveOffset)
      highestSaveOffset = Offset;
    switch(Register) {
      case regEnconding::EBX:
        if (e.flags2.ebx_saved)
          report_fatal_error("EBX saved more than once in the same prolog!");
        ebxSaveOffset = Offset;
        e.flags2.ebx_saved = 1;
        break;
      case regEnconding::ESI:
        if (e.flags2.esi_saved)
          report_fatal_error("ESI saved more than once in the same prolog!");
        esiSaveOffset = Offset;
        e.flags2.esi_saved = 1;
        break;
      case regEnconding::EDI:
        if (e.flags2.edi_saved)
          report_fatal_error("EDI saved more than once in the same prolog!");
        ediSaveOffset = Offset;
        e.flags2.edi_saved = 1;
        break;
      default:
        report_fatal_error("VOS only supports saving EBP, EBX, ESI and EDI!");
        break;
    }
  }
}

void VosEHFrameInfo::EmitWinCFISaveXMM(unsigned Register, unsigned Offset) {
  entryOpProcessed = true;
  report_fatal_error("Saved XMM regs not supported on VOS!");
}

void VosEHFrameInfo::EmitWinCFIPushFrame(bool Code) {
  if (entryOpProcessed)
    report_fatal_error("If present, PushMachFrame must be the first UOP");

  entryOpProcessed = true;
}

void VosEHFrameInfo::EmitWinCFIEndProlog() {
  entryOpProcessed = true;
  MCSymbol *Label = Streamer.EmitCFILabel();
  BlockMapItem B = BlockMapItem(Body, Label, Symbol);
  UnwindEmitter.InsertBlockMapItem(B);
}

void VosEHFrameInfo::EmitWinCFIGotSaveOffset(unsigned Offset) {
  e.flags2.GOTP_in_on_unit_slot = true;
  GotSaveOffset = Offset;
}

void VosEHFrameInfo::EmitWinCFISaveBasePtr(unsigned Register, unsigned FrameOffset,
                                      unsigned FrameEndSize) {
  if (FrameOffset & 0x03)
    report_fatal_error("Misaligned saved base pointer register offset!");
  
  frameEndPointerOffiset = FrameOffset;
  e.frame_end_size = FrameEndSize;
}

void VosEHFrameInfo::EmitWinCFIBeginEpilog() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  BlockMapItem EPI = BlockMapItem(Epilog, Label, Symbol);
  UnwindEmitter.InsertBlockMapItem(EPI);
}

void VosEHFrameInfo::EmitWinCFIEndEpilog() {
  MCSymbol *Label = Streamer.EmitCFILabel();
  
  BlockMapItem EPI = BlockMapItem(Body, Label, Symbol);
  UnwindEmitter.InsertBlockMapItem(EPI);
}

void VosEHFrameInfo::EmitWinEHHandler(const MCSymbol *Sym, bool Unwind,
                                 bool Except) {
  ExceptionHandler = Sym;
  if (Unwind)
    HandlesUnwind = true;
  if (Except)
    HandlesExceptions = true;
}

void VosEHFrameInfo::EmitWinEHHandlerTable(const MCSymbol *Table) {
  ExceptionHandler = Table;
}

void VosEHFrameInfo::EmitWinEHHandlerData() {
  if (ChainedParent)
    report_fatal_error("Chained unwind areas can't have handlers!");
  
  // Switch sections. Don't call SwitchSection directly, because that will
  // cause the section switch to be visible in the emitted assembly.
  // We only do this so the section switch that terminates the handler
  // data block is visible.
  MCSection *EntryBlocks =
       Streamer.getContext().getELFSection(".VOS.entry_block",
                                                 ELF::SHT_PROGBITS,
                                                 ELF::SHF_ALLOC);
  Streamer.SwitchSectionNoChange(EntryBlocks);
}

bool VosEHFrameInfo::isValidWinFrameInfo()
{
  return !End;
}
SEHFrameInfo *VosEHFrameInfo::GetChainedParent()
{
  return ChainedParent;
}

void VosEHFrameInfo::EmitUnwindInfo()  {
  MCContext &context = Streamer.getContext();
  MCSection *EntryBlocks = context.getELFSection(".VOS.entry_block",
                                                 ELF::SHT_PROGBITS,
                                                 ELF::SHF_ALLOC);
  Streamer.PushSection();
  Streamer.SwitchSection(EntryBlocks);
  // Generate these entry blocks on the fly
  EmitVosUnwindInfoImpl();
  Streamer.PopSection();
}

static void EmitSymbolOffset(MCStreamer &streamer,
                                 const MCSymbol *Base,
                                 const MCSymbol *Other) {
  MCContext &Context = streamer.getContext();
  const MCSymbolRefExpr *BaseRef = MCSymbolRefExpr::create(Base, Context);
  const MCSymbolRefExpr *OtherRef = MCSymbolRefExpr::create(Other, Context);
  const MCExpr *Ofs = MCBinaryExpr::createSub(OtherRef, BaseRef, Context);
  streamer.EmitValue(Ofs, 4);
}

void VosEHFrameInfo::EmitVosUnwindInfoImpl() {

  if (AlreadyEmitted)
    return;
  
  AlreadyEmitted = true;

  if (registerPushedBeforeFrame + registerPushedAfterFrame + registerSaved > 1)
    report_fatal_error("Not one of the VOS supported prolog types");

  if (registerPushedAfterFrame) {
    // Legacy type 1 prolog type
    e.reg_save_area_offset = e.frame_size - regsPushed - 4;
    e.flags2.prologue_epilogue_type = 1;
  }
  else if (registerSaved) {
    // Fast save register type prolog and epilog
    e.flags2.prologue_epilogue_type = 3;

    assert(ebxSaveOffset <= 4 && esiSaveOffset <= 4 && ediSaveOffset <= 4);
    e.reg_save_area_offset = highestSaveOffset + 4;
    if (e.flags2.ebp_saved && ebpSaveOffset != 0)
      report_fatal_error("EBP must be saved at frame pointer for VOS type 3 prolog");

    uint32_t ebx_slot = e.flags2.ebx_saved ? (highestSaveOffset - ebxSaveOffset) >> 2 : 0;
    uint32_t esi_slot = e.flags2.esi_saved ? (highestSaveOffset - esiSaveOffset) >> 2 : 0;
    uint32_t edi_slot = e.flags2.edi_saved ? (highestSaveOffset - ediSaveOffset) >> 2 : 0;
    
    if (ebx_slot > 3 || esi_slot > 3 || edi_slot > 3)
      report_fatal_error("EBX, ESI and EDI must be saved together");
    
    e.flags2.ebx_saved = ebx_slot;
    e.flags2.esi_saved = esi_slot;
    e.flags2.edi_saved = edi_slot;
  }
  else {
    // Most typical "push all regs first" epilog
    e.flags2.prologue_epilogue_type = 2;
  }

  assert(e.reg_save_area_offset <= 4 && e.reg_save_area_offset > -e.frame_size);

  // Insert Extra Stuff for LLVM unwinding.
  // These come before the entry block; so, the unwinder will have to
  // parse backards:  First, it will optionally back up 4 bytes and pick up
  // the stack frame offset for gotp, if not present then either gotp isn't
  // needed or it isn't PIC code.
  // If e.flags2.ChainedParent, then back up and use the following structure:
  // struct {
  //    int32_t ParentEntryBlockOffset;
  //    int32_t ParentFunctionOffset;
  //    int32_t ParentBegin;
  //    int32_t parentEnd;
  // }
  // These offsets are all relative to the entry block pointer.
  //
  // Otherwise, if e.flags2.HasExceptionPersonality, then back up and use
  // struct {
  //    int32_t FunctionGotOff;         // relative to GOTP, real function ptr
  //    int32_t PersonalityTableOffset; // relative to entry block pointer
  // }
  //
  // The parameters to the personality functions are TBD, but they should
  // include the personality table, GOTP (becuase they need to pass it to
  // funclets), the unwind_info structure which needs to be extended to pass
  // along whatever exception description info C++ needs.
  // The
  
  Streamer.EmitValueToAlignment(4);

  // Do the prefix little endian, because the GOTP relocation for function
  // pointers only works little endian.
  Streamer.PushLittleEndian();
  
  if (ChainedParent) {
    e.flags2.chained_parent = true;

    EmitSymbolOffset(Streamer, Symbol, ChainedParent->Symbol);
  }
  else if ((HandlesUnwind | HandlesExceptions) && ExceptionHandlerTable) {
    e.flags2.has_exception_personality = true;

    if (e.flags2.GOTP_in_on_unit_slot) {
      Streamer.EmitValue(MCSymbolRefExpr::create(ExceptionHandler,
                                                 MCSymbolRefExpr::VK_GOT,
                                                 getContext()), 4);
    }
    else {
      Streamer.EmitValue(MCSymbolRefExpr::create(ExceptionHandler,
                                                 MCSymbolRefExpr::VK_None,
                                                 getContext()), 4);
    }

    EmitSymbolOffset(Streamer, Symbol, ExceptionHandlerTable);
  }

  Streamer.PopEndian();
  
  // Now, emit the entry block.
  Streamer.EmitLabel(Symbol);
  Streamer.PushBigEndian();
  Streamer.EmitIntValue(e.symtab_addr, 4, true);
  Streamer.EmitIntValue(e.block_node_addr, 4, true);
  Streamer.EmitIntValue(e.frame_size, 4, true);
  Streamer.EmitIntValue(e.reg_save_area_offset, 4, true);
  Streamer.EmitIntValue(e.uflags2.bin, 4, true);
  Streamer.EmitIntValue(e.flags, 2, true);
  Streamer.EmitIntValue(e.fap_offset, 2, true);
  Streamer.EmitIntValue(e.frame_end_size, 2, true);
  Streamer.EmitIntValue(e.n_args, 2, true);
  Streamer.EmitIntValue(e.name.len, 2, true);
  Streamer.EmitBytes(FunctionName);
  Streamer.PopEndian();
}

BlockMapItem::BlockMapItem(enum BlockMapReferenceType RefType,
                           const MCSymbol *CLabel, const MCSymbol *EBLabel) {
  
  ReferenceType = RefType;
  CodeLabel = CLabel;
  EntryBlockLabel = EBLabel;
}

void llvm::VosEHUnwindEmitter::InsertBlockMapItem(
                                                  BlockMapItem &Item) {
  
  // std::pair<BlockMapType::iterator, bool> res;
  BlockMap.insert(BlockMap.end(), Item);
}

bool llvm::VosEHUnwindEmitter::BlockMapCompare(
                                               const BlockMapItem &a, const BlockMapItem &b) {
  
  return a.getCodeOffset() < b.getCodeOffset();
}

void llvm::VosEHUnwindEmitter::Emit(MCStreamer &Streamer) {

  if (Streamer.getNumWinFrameInfos() <= 0)
    return;

  MCContext &context = Streamer.getContext();

  Streamer.PushSection();
  MCSection *EntryBlocks = context.getELFSection(".VOS.entry_block",
                                                 ELF::SHT_PROGBITS,
                                                 ELF::SHF_ALLOC);
  Streamer.SwitchSection(EntryBlocks);

  // Generate any remaining entry blocks.
  for (SEHFrameInfo *CFII : Streamer.getWinFrameInfos()) {
    VosEHFrameInfo *CFI = (VosEHFrameInfo *) CFII;
    CFI->EmitVosUnwindInfoImpl();
  }

  Streamer.PopSection();

  // If there aren't any entry blocks, we don't need a block map either.
  if (BlockMap.empty())
    return;
  
  // First, set the section.  Switch the section first, because that will
  // flush out any cached labels for the sort.
  MCSection *BlockMapSection = context.getELFSection(".VOS.block_map",
                                                     ELF::SHT_PROGBITS,
                                                     ELF::SHF_ALLOC);
  Streamer.PushSection();
  Streamer.SwitchSection(BlockMapSection);
  Streamer.PushLittleEndian();

  // Now, sort and emit the actual block map.
  std::sort(BlockMap.begin(), BlockMap.end(), BlockMapCompare);

  // Then loop through the block map (which is native endian).
  uint32_t prevOffset = 0;
  enum BlockMapReferenceType prevRefType = EndOfCode;
  uint32_t prevEB = 0;
  for (const BlockMapType::value_type &M : BlockMap) {
    uint32_t Offset = M.getCodeOffset();
    enum BlockMapReferenceType RefType = M.getReferenceType();
    uint32_t EB = M.getEntryBlockOffset();
 
    // The low order 2 bits of the entry block offset must be clear.
    assert((EB & 3) == 0);
    
    // Prioritize any duplicates.
    if (Offset == prevOffset) {
      // Eliminate complete duplicates.
      if (prevRefType == RefType && prevEB == EB)
        continue;

      switch(prevRefType) {
        case Prolog:
          // Prologs can be empty; so, only itch duplicate Ends.
          if (RefType == EndOfCode)
            continue;
         break;
        case Epilog:
          // Epilogs must at least have a return; so, they can't be duplicate.
          assert(RefType != Epilog);
          continue;
        case Body:
        case BodyPlus4:
          // Prologs can be empty and we always ditch duplicate Ends.
          if (RefType == EndOfCode || RefType == Prolog)
            continue;
          break;

        case EndOfCode:;
          // It's always OK if the previous end runs into more code.
      }
     } else {
      Streamer.EmitIntValue(prevOffset, 4);
      Streamer.EmitIntValue(prevRefType == EndOfCode ? 0 : (prevEB | prevRefType), 4);
    }
 
    prevOffset = Offset;
    prevRefType = RefType;
    prevEB = EB;
  }

  // Kick out the final entry.
  Streamer.EmitIntValue(prevOffset, 4);
  Streamer.EmitIntValue(prevRefType == EndOfCode ? 0 : (prevEB | prevRefType), 4);
  Streamer.PopEndian();
  Streamer.PopSection();

  // Don't need the block map any more.
  BlockMap.clear();
}

VosEHUnwindEmitter::~VosEHUnwindEmitter() {}
                    
SEHFrameInfo *VosEHUnwindEmitter::createSEHFrameInfo(MCStreamer *Streamer,
                                                     SEHFrameInfo *ChainedParent)
{
  return new VosEHFrameInfo(Streamer, this, ChainedParent);
}
