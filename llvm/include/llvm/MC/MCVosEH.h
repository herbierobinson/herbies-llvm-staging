//===- MCVOSEH.h - Machine Code Vos EH support, based on Win64EH -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains declarations to support the Win64 Exception Handling
// scheme in MC.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCVOSEH_H
#define LLVM_MC_MCVOSEH_H

#include <map>
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"

// VOS takes advantage of the windows functions collecting most of the
// information we need.  We will generate vastly different unwind
// tables.  We could probably generate what we need from the Dwarf info, too,
// but given that the unwinder wants SEH code, it seemed safer to depend on
// the corresponding unwinder database.

namespace llvm {
class VosEHUnwindEmitter;

    enum BlockMapReferenceType {Body = 0, Prolog = 1, Epilog = 2, BodyPlus4 = 3,
      EndOfCode = 4};

class BlockMapItem {
  enum BlockMapReferenceType ReferenceType;
  const MCSymbol *CodeLabel;
  const MCSymbol *EntryBlockLabel;
public:
  BlockMapItem(enum BlockMapReferenceType RefType,
               const MCSymbol *CLabel,
               const MCSymbol *EBLabel = nullptr);
  inline BlockMapItem(void) {BlockMapItem(EndOfCode, nullptr);}
  
  inline enum BlockMapReferenceType getReferenceType() const
  { return ReferenceType; }
  
  inline const MCSymbol *getCodeLabel(void)  { return CodeLabel; }
  inline const MCSymbol *getEntryBlockLabel(void)  { return EntryBlockLabel; }
  inline uint32_t getCodeOffset(void) const
  { return CodeLabel->getOffset(); }
  inline uint32_t getEntryBlockOffset(void) const
  { return EntryBlockLabel ? EntryBlockLabel->getOffset() : 0; }
};
  
typedef std::vector<BlockMapItem> BlockMapType;
  

class VosEHFrameInfo: public SEHFrameInfo {
  
  typedef union {
    struct entry_block_flags2
    {
      uint32_t            entry_block_ptr_saved : 1;
      uint32_t            on_unit_ptr_saved : 1;
      uint32_t            display_ptr_saved : 1;
      uint32_t            orig_frame_end_ptr_saved : 1;
      uint32_t            fp_in_reg      : 1;
      uint32_t            ebp_saved      : 1;
      uint32_t            ebx_saved      : 2;
      uint32_t            esi_saved      : 2;
      uint32_t            edi_saved      : 2;
      uint32_t            rtn_buffer_handling : 2;
      uint32_t            rtn_pointer_type : 2;
      uint32_t            ds_saved       : 1;
      uint32_t            es_saved       : 1;
      uint32_t            glue_code      : 1;
      uint32_t            orig_frame_end_ptr_is_sp : 1;
      uint32_t            chained_parent : 1;
      uint32_t            has_exception_personality: 1;
      uint32_t            GOTP_in_on_unit_slot: 1;
      uint32_t            fap_offset_is_SEHFrameOffset : 1; // Needed?
      uint32_t            mbz            : 5;
      unsigned            prologue_epilogue_type : 3;
    } bits;
    uint32_t            bin;
  }  entry_block_flags2;

  typedef struct
  {
    int32_t               symtab_addr;
    int32_t               block_node_addr;
    int32_t               frame_size;
    int32_t               reg_save_area_offset;
    entry_block_flags2    uflags2;
#define flags2 uflags2.bits
    uint16_t              flags;
    
#define entry_block_ia32_flags_is_subroutine 0x8000
#define entry_block_ia32_flags_is_function 0x4000
#define entry_block_ia32_flags_main     0x2000
#define entry_block_ia32_flags_support  0x1000
#define entry_block_ia32_flags_kernel   0x0800
#define entry_block_ia32_flags_has_fac  0x0400
#define entry_block_ia32_flags_fault_handler 0x0200
#define entry_block_ia32_flags_command_args 0x0100
#define entry_block_ia32_flags_signaller 0x0080
#define entry_block_ia32_flags_full_table 0x0040
#define entry_block_ia32_flags_save_registers 0x0020
#define entry_block_ia32_flags_pop      0x0010
#define entry_block_ia32_flags_unwinder 0x0008
#define entry_block_ia32_flags_mbz_mask 0x0007
#define entry_block_ia32_flags_mbz_shift 0
    
    int16_t               fap_offset;
    int16_t               frame_end_size;
    int16_t               n_args;
    struct {
      int16_t             len;
      char                text[4];
    }                     name;
  } entry_block_ia32;
  
  typedef enum regEnconding {
    EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI
  } regEnconding;
  
  MCStreamer &Streamer;
  VosEHUnwindEmitter &UnwindEmitter;
  SEHFrameInfo *ChainedParent = nullptr;
  bool AlreadyEmitted = false;
  bool HandlesUnwind = false;
  bool HandlesExceptions = false;
  const MCSymbol *ExceptionHandler = nullptr;
  const MCSymbol *ExceptionHandlerTable = nullptr;

  llvm::StringRef FunctionName;
  entry_block_ia32 e;
  
  bool entryOpProcessed = false;
  bool registerPushedBeforeFrame = false;
  bool registerPushedAfterFrame = false;
  bool registerSaved = false;
  uint32_t highestSaveOffset = 0;
  uint32_t ebpSaveOffset = 0;
  uint32_t ebxSaveOffset = 0;
  uint32_t esiSaveOffset = 0;
  uint32_t ediSaveOffset = 0;
  uint32_t frameEndPointerOffiset = 0;
  int32_t GotSaveOffset = 0;
  bool frameUpdated = false;
  int16_t regsPushed = 0;
  
public:
  VosEHFrameInfo(MCStreamer *Streamer, VosEHUnwindEmitter *UnwindEmitter, SEHFrameInfo *ChainedParent);
  virtual ~VosEHFrameInfo();
  
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
  virtual void EmitWinEHHandlerTable(const MCSymbol *Table) override;
  virtual void EmitWinEHHandlerData() override;
  
  virtual void EmitUnwindInfo() override;
  void EmitVosUnwindInfoImpl();
  
  virtual bool isValidWinFrameInfo() override;
  virtual SEHFrameInfo *GetChainedParent() override;
    
private:

  void EmitLabel(MCSymbol *Symbol) { Streamer.EmitLabel(Symbol); }
  MCContext &getContext() const { return Streamer.getContext(); }
};
  

class VosEHUnwindEmitter : public SEHUnwindEmitter {

  BlockMapType BlockMap;

public:
  virtual ~VosEHUnwindEmitter();

  virtual SEHFrameInfo *createSEHFrameInfo(MCStreamer *Streamer,
                                           SEHFrameInfo *PrevFrame = nullptr) override;
  
  void Emit(MCStreamer &Streamer) override;

  void InsertBlockMapItem(BlockMapItem &Item);

private:
  static bool BlockMapCompare(const BlockMapItem &a, const BlockMapItem &b);
};
} // end namespace llvm

#endif
