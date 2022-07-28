//===-- X86ELFObjectWriter.cpp - X86 ELF Writer ---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/X86FixupKinds.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/ErrorHandling.h"
#include <cassert>
#include <cstdint>

using namespace llvm;

namespace {

class X86ELFObjectWriter : public MCELFObjectTargetWriter {
public:
  X86ELFObjectWriter(bool IsELF64, uint8_t OSABI, uint16_t EMachine,
                     bool ByteSwapedRelocationsSupported = false);
  ~X86ELFObjectWriter() override = default;

protected:
  unsigned getRelocType(MCContext &Ctx, const MCValue &Target,
                        const MCFixup &Fixup, bool IsPCRel) const override;
};

class X86_VOS_ELFObjectWriter : public X86ELFObjectWriter {
public:
  X86_VOS_ELFObjectWriter(bool IsELF64, uint8_t OSABI, uint16_t EMachine);
  
  ~X86_VOS_ELFObjectWriter() override;
  
protected:
  unsigned getRelocType(MCContext &Ctx, const MCValue &Target,
                        const MCFixup &Fixup, bool IsPCRel) const override;
};

} // end anonymous namespace

X86ELFObjectWriter::X86ELFObjectWriter(bool IsELF64, uint8_t OSABI,
                                       uint16_t EMachine,
                                       bool ByteSwapedRelocationsSupported)
    : MCELFObjectTargetWriter(IsELF64, OSABI, EMachine,
                              // Only i386 and IAMCU use Rel instead of RelA.
                              /*HasRelocationAddend*/
                              (EMachine != ELF::EM_386) &&
                                  (EMachine != ELF::EM_IAMCU), false,
                              ByteSwapedRelocationsSupported) {}

X86_VOS_ELFObjectWriter::X86_VOS_ELFObjectWriter(bool IsELF64, uint8_t OSABI,
                                       uint16_t EMachine)
: X86ELFObjectWriter(IsELF64, OSABI, EMachine, true) {}

X86_VOS_ELFObjectWriter::~X86_VOS_ELFObjectWriter()
{}

enum X86_64RelType { RT64_64, RT64_32, RT64_32S, RT64_16, RT64_8 };

static X86_64RelType getType64(unsigned Kind,
                               MCSymbolRefExpr::VariantKind &Modifier,
                               bool &IsPCRel) {
  switch (Kind) {
  default:
    llvm_unreachable("Unimplemented");
  case X86::reloc_global_offset_table8:
    Modifier = MCSymbolRefExpr::VK_GOT;
    IsPCRel = true;
    return RT64_64;
  case FK_Data_8:
    return RT64_64;
  case X86::reloc_signed_4byte:
  case X86::reloc_signed_4byte_relax:
    if (Modifier == MCSymbolRefExpr::VK_None && !IsPCRel)
      return RT64_32S;
    return RT64_32;
  case X86::reloc_global_offset_table:
    Modifier = MCSymbolRefExpr::VK_GOT;
    IsPCRel = true;
    return RT64_32;
  case FK_Data_4:
  case FK_PCRel_4:
  case X86::reloc_riprel_4byte:
  case X86::reloc_riprel_4byte_relax:
  case X86::reloc_riprel_4byte_relax_rex:
  case X86::reloc_riprel_4byte_movq_load:
    return RT64_32;
  case FK_PCRel_2:
  case FK_Data_2:
    return RT64_16;
  case FK_PCRel_1:
  case FK_Data_1:
    return RT64_8;
  }
}

static void checkIs32(MCContext &Ctx, SMLoc Loc, X86_64RelType Type) {
  if (Type != RT64_32)
    Ctx.reportError(Loc,
                    "32 bit reloc applied to a field with a different size");
}

static unsigned getRelocType64(MCContext &Ctx, SMLoc Loc,
                               MCSymbolRefExpr::VariantKind Modifier,
                               X86_64RelType Type, bool IsPCRel,
                               unsigned Kind) {
  switch (Modifier) {
  default:
    llvm_unreachable("Unimplemented");
  case MCSymbolRefExpr::VK_None:
  case MCSymbolRefExpr::VK_X86_ABS8:
    switch (Type) {
    case RT64_64:
      return IsPCRel ? ELF::R_X86_64_PC64 : ELF::R_X86_64_64;
    case RT64_32:
      return IsPCRel ? ELF::R_X86_64_PC32 : ELF::R_X86_64_32;
    case RT64_32S:
      return ELF::R_X86_64_32S;
    case RT64_16:
      return IsPCRel ? ELF::R_X86_64_PC16 : ELF::R_X86_64_16;
    case RT64_8:
      return IsPCRel ? ELF::R_X86_64_PC8 : ELF::R_X86_64_8;
    }
  case MCSymbolRefExpr::VK_GOT:
    switch (Type) {
    case RT64_64:
      return IsPCRel ? ELF::R_X86_64_GOTPC64 : ELF::R_X86_64_GOT64;
    case RT64_32:
      return IsPCRel ? ELF::R_X86_64_GOTPC32 : ELF::R_X86_64_GOT32;
    case RT64_32S:
    case RT64_16:
    case RT64_8:
      llvm_unreachable("Unimplemented");
    }
  case MCSymbolRefExpr::VK_GOTOFF:
    assert(Type == RT64_64);
    assert(!IsPCRel);
    return ELF::R_X86_64_GOTOFF64;
  case MCSymbolRefExpr::VK_TPOFF:
    assert(!IsPCRel);
    switch (Type) {
    case RT64_64:
      return ELF::R_X86_64_TPOFF64;
    case RT64_32:
      return ELF::R_X86_64_TPOFF32;
    case RT64_32S:
    case RT64_16:
    case RT64_8:
      llvm_unreachable("Unimplemented");
    }
  case MCSymbolRefExpr::VK_DTPOFF:
    assert(!IsPCRel);
    switch (Type) {
    case RT64_64:
      return ELF::R_X86_64_DTPOFF64;
    case RT64_32:
      return ELF::R_X86_64_DTPOFF32;
    case RT64_32S:
    case RT64_16:
    case RT64_8:
      llvm_unreachable("Unimplemented");
    }
  case MCSymbolRefExpr::VK_SIZE:
    assert(!IsPCRel);
    switch (Type) {
    case RT64_64:
      return ELF::R_X86_64_SIZE64;
    case RT64_32:
      return ELF::R_X86_64_SIZE32;
    case RT64_32S:
    case RT64_16:
    case RT64_8:
      llvm_unreachable("Unimplemented");
    }
  case MCSymbolRefExpr::VK_TLSCALL:
    return ELF::R_X86_64_TLSDESC_CALL;
  case MCSymbolRefExpr::VK_TLSDESC:
    return ELF::R_X86_64_GOTPC32_TLSDESC;
  case MCSymbolRefExpr::VK_TLSGD:
    checkIs32(Ctx, Loc, Type);
    return ELF::R_X86_64_TLSGD;
  case MCSymbolRefExpr::VK_GOTTPOFF:
    checkIs32(Ctx, Loc, Type);
    return ELF::R_X86_64_GOTTPOFF;
  case MCSymbolRefExpr::VK_TLSLD:
    checkIs32(Ctx, Loc, Type);
    return ELF::R_X86_64_TLSLD;
  case MCSymbolRefExpr::VK_PLT:
    checkIs32(Ctx, Loc, Type);
    return ELF::R_X86_64_PLT32;
  case MCSymbolRefExpr::VK_GOTPCREL:
    checkIs32(Ctx, Loc, Type);
    // Older versions of ld.bfd/ld.gold/lld
    // do not support GOTPCRELX/REX_GOTPCRELX,
    // and we want to keep back-compatibility.
    if (!Ctx.getAsmInfo()->canRelaxRelocations())
      return ELF::R_X86_64_GOTPCREL;
    switch (Kind) {
    default:
      return ELF::R_X86_64_GOTPCREL;
    case X86::reloc_riprel_4byte_relax:
      return ELF::R_X86_64_GOTPCRELX;
    case X86::reloc_riprel_4byte_relax_rex:
    case X86::reloc_riprel_4byte_movq_load:
      return ELF::R_X86_64_REX_GOTPCRELX;
    }
  }
}

enum X86_32RelType { RT32_32, RT32_16, RT32_8 };

static X86_32RelType getType32(X86_64RelType T) {
  switch (T) {
  case RT64_64:
    llvm_unreachable("Unimplemented");
  case RT64_32:
  case RT64_32S:
    return RT32_32;
  case RT64_16:
    return RT32_16;
  case RT64_8:
    return RT32_8;
  }
  llvm_unreachable("unexpected relocation type!");
}

static unsigned getRelocType32(MCContext &Ctx,
                               MCSymbolRefExpr::VariantKind Modifier,
                               X86_32RelType Type, bool IsPCRel,
                               unsigned Kind) {
  switch (Modifier) {
  default:
    llvm_unreachable("Unimplemented");
  case MCSymbolRefExpr::VK_None:
  case MCSymbolRefExpr::VK_X86_ABS8:
    switch (Type) {
    case RT32_32:
      return IsPCRel ? ELF::R_386_PC32 : ELF::R_386_32;
    case RT32_16:
      return IsPCRel ? ELF::R_386_PC16 : ELF::R_386_16;
    case RT32_8:
      return IsPCRel ? ELF::R_386_PC8 : ELF::R_386_8;
    }
  case MCSymbolRefExpr::VK_GOT:
    assert(Type == RT32_32);
    if (IsPCRel)
      return ELF::R_386_GOTPC;
    // Older versions of ld.bfd/ld.gold/lld do not support R_386_GOT32X and we
    // want to maintain compatibility.
    if (!Ctx.getAsmInfo()->canRelaxRelocations())
      return ELF::R_386_GOT32;

    return Kind == X86::reloc_signed_4byte_relax ? ELF::R_386_GOT32X
                                                 : ELF::R_386_GOT32;
  case MCSymbolRefExpr::VK_GOTOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_GOTOFF;
  case MCSymbolRefExpr::VK_TPOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_LE_32;
  case MCSymbolRefExpr::VK_DTPOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_LDO_32;
  case MCSymbolRefExpr::VK_TLSGD:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_GD;
  case MCSymbolRefExpr::VK_GOTTPOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_IE_32;
  case MCSymbolRefExpr::VK_PLT:
    assert(Type == RT32_32);
    return ELF::R_386_PLT32;
  case MCSymbolRefExpr::VK_INDNTPOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_IE;
  case MCSymbolRefExpr::VK_NTPOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_LE;
  case MCSymbolRefExpr::VK_GOTNTPOFF:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_GOTIE;
  case MCSymbolRefExpr::VK_TLSLDM:
    assert(Type == RT32_32);
    assert(!IsPCRel);
    return ELF::R_386_TLS_LDM;
  }
}

unsigned X86ELFObjectWriter::getRelocType(MCContext &Ctx, const MCValue &Target,
                                          const MCFixup &Fixup,
                                          bool IsPCRel) const {
  MCSymbolRefExpr::VariantKind Modifier = Target.getAccessVariant();
  unsigned Kind = Fixup.getKind();
  X86_64RelType Type = getType64(Kind, Modifier, IsPCRel);
  if (getEMachine() == ELF::EM_X86_64)
    return getRelocType64(Ctx, Fixup.getLoc(), Modifier, Type, IsPCRel, Kind);

  assert((getEMachine() == ELF::EM_386 || getEMachine() == ELF::EM_IAMCU) &&
         "Unsupported ELF machine type.");
  return getRelocType32(Ctx, Modifier, getType32(Type), IsPCRel, Kind);
}

unsigned X86_VOS_ELFObjectWriter::getRelocType(MCContext &Ctx, const MCValue &Target, const MCFixup &Fixup, bool IsPCRel) const
{
  MCSymbolRefExpr::VariantKind Modifier = Target.getAccessVariant();
  unsigned Kind = Fixup.getKind();
  X86_64RelType Type = getType64(Fixup.getKind(), Modifier, IsPCRel);
  X86_32RelType Type32 = getType32(Type);
  if (getEMachine() == ELF::EM_X86_64)
    return getRelocType64(Ctx, Fixup.getLoc(), Modifier, Type, IsPCRel,
                          Fixup.getKind());
  
  assert((getEMachine() == ELF::EM_386 || getEMachine() == ELF::EM_IAMCU) &&
         "Unsupported ELF machine type.");

  bool bswap = Fixup.getBswap();
  const MCSymbolRefExpr *symA = Target.getSymA();
  bool IsFunction = symA->getSymbol().isFunction();
  const MCSymbolRefExpr *symB = Target.getSymA();

  // Implement the VOS extensions for function pointers.
  // Other references are from code, must be little endian and are
  // supported by the VOS binder.
  if (IsFunction) {
    if (!symB && !IsPCRel && Type32 == RT32_32) {

          switch (Modifier) {
          default:
              break;
          case MCSymbolRefExpr::VK_None:
              if (bswap)
                return ELF::R_386VOS_FPTR32MSB;
              return ELF::R_386VOS_FPTR32;
            case MCSymbolRefExpr::VK_GOT:
              if (!bswap)
                return ELF::R_386VOS_GOT_FPTR32;
              break;
            case MCSymbolRefExpr::VK_GOTOFF:
              break;
         }
    }
  }

  // Pick off any remaining byte swapped relocations supported by the
  // VOS binder.
  if (bswap) {
    if (!symB && Modifier == MCSymbolRefExpr::VK_None && Type32 == RT32_32) {
      return (IsPCRel) ? ELF::R_386VOS_PC32MSB : ELF::R_386VOS_32_MSB;
    }

    // The standard relocations do not support byte swapping; so, if
    // the compiler asks for anything else, choke on it.
    llvm_unreachable("Unimplemented");
  }

  // Map to the standard relocation types.
  unsigned relocType = getRelocType32(Ctx, Modifier, Type32, IsPCRel, Kind);

  switch (relocType) {
    case ELF::R_386_NONE:
    case ELF::R_386_32:
    case ELF::R_386_PC32:
    case ELF::R_386_GOT32:
    case ELF::R_386_PLT32:
    case ELF::R_386_GOTOFF:
    case ELF::R_386_GOTPC:
#if 0
    // The Stratus documentation (sed-2811) states that the following is a
    // Solaris extension to the ABI, but doesn't actually say whether
    // the binder implements it.  If it turns out to be needed, we'll need
    // to check the binder code and add them if necessary.
    // R_386_32PLT is not generated by getRelocType32.  R_386_PLT32 is
    // generated instead.
    case ELF::R_386_32PLT:
    // The Stratus documentation (sed-2811) states that the following are
    // GNU extensions to the ABI, but doesn't actually say whether
    // the binder implements them.  If they turn out to be needed, we'll need
    // to check the binder code and add them if necessary.
    // All of the following are generated by getRelocType32, but I'm not
    // so sure the 8 and 16 bit relocation will have any practical use.
    case ELF::R_386_16:
    case ELF::R_386_PC16:
    case ELF::R_386_8:
    case ELF::R_386_PC8:
#endif
      return relocType;
    default:
      
      // Only the relocation types are supported by the VOS binder.
      llvm_unreachable("Unimplemented");
  }
}


MCObjectWriter *llvm::createX86ELFObjectWriter(raw_pwrite_stream &OS,
                                               bool IsELF64, uint8_t OSABI,
                                               uint16_t EMachine) {
  MCELFObjectTargetWriter *MOTW =
  (OSABI == ELF::ELFOSABI_OPENVOS)
     ? new X86_VOS_ELFObjectWriter(IsELF64, OSABI, EMachine)
     : new X86ELFObjectWriter(IsELF64, OSABI, EMachine);
  return createELFObjectWriter(MOTW, OS,  /*IsLittleEndian=*/true);
}
