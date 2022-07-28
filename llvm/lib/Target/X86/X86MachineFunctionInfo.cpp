//===-- X86MachineFunctionInfo.cpp - X86 machine function info ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "X86MachineFunctionInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "X86RegisterInfo.h"
#include "llvm/Target/TargetSubtargetInfo.h"

using namespace llvm;

void X86MachineFunctionInfo::anchor() { }

void X86MachineFunctionInfo::setSpecialFrameSlotPresent(const MachineFunction *MF,
                                                        SpecialFrameSlotType t) {
  if (!SpecialFrameSlotPresent[t]) {
    const X86RegisterInfo *RegInfo = static_cast<const X86RegisterInfo *>
                                            (MF->getSubtarget().getRegisterInfo());
    unsigned SlotSize = RegInfo->getSlotSize();
    if (!SpecialFrameSlotAllocator) {
      for (const MCPhysReg *CSR =
           RegInfo->X86RegisterInfo::getCalleeSavedRegs(MF);
           unsigned Reg = *CSR;
           ++CSR)
      {
        if (X86::GR64RegClass.contains(Reg) || X86::GR32RegClass.contains(Reg))
          SpecialFrameSlotAllocator -= SlotSize;
      }
      LastSavedRegSlot = SpecialFrameSlotAllocator;
    }

    const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
    if (STI.isTargetVos() && SlotSize == 4) {
      // VOS 32 bit uses fixed stack locations.
      switch(t) {
        case RestoreBasePointer:
          SpecialFrameSlotOffset[t] = -20;
          break;
        case ExceptionHandlerGOTP:
          SpecialFrameSlotOffset[t] = -28;
          break;
        default:
          return;
      }
      
      if (SpecialFrameSlotAllocator > SpecialFrameSlotOffset[t])
        SpecialFrameSlotAllocator = SpecialFrameSlotOffset[t];
    }
    else {
      SpecialFrameSlotAllocator -= SlotSize;
      SpecialFrameSlotOffset[t] = SpecialFrameSlotAllocator;
    }

    SpecialFrameSlotPresent[t] = true;
  }
}

void X86MachineFunctionInfo::updateFrameSizeForSpecialSlots(uint64_t &FrameSize)
const {

  if (LastSavedRegSlot) {
    int RegSaveOffset = -getCalleeSavedFrameSize();
    assert(LastSavedRegSlot == RegSaveOffset);

    FrameSize += (SpecialFrameSlotAllocator - LastSavedRegSlot);
  }
}
