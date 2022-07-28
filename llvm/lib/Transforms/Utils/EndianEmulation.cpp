//===- EndianEmulation.cpp - Emulate Selected Endianess --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The EndianEmulation transformation inserts bswap instructions to
// present an API which is big endian or little endian based on a program
// option irrespecitve of the underlying hardware support.
// This option is useful when one has a large code base that is impractical
// to use with hardware with the wrong endianess.
// This can happen for large communication programs where ordering on the
// wire is, by definition, endian dependent.
// It can also happen when there is a large disk based database that is
// impractical to convert -- or imposssible to convert due to availability
// constraints.
// Yes, it is possible to convert such code by adding bswap calls pervasively,
// but the cost of doing this can be substantial and compilers are supposed
// to make programming easier.
// If properly optimized, the cost of endian emulation is only around 10%
// in CPU runtime.
// Endian emulation is supported for transportable data types (1, 8,
// 16, 32 and 64 bit intergers, 32 and 64 bit float, pointers, and aggregates
// with these types.
// In particular, it is not supported for machine dependent types like
// 80 and 128 bit floating point.
//===----------------------------------------------------------------------===//

// Alternatively, the target triple could be defined as supporting AnyEndianness
// and should implement the byte swapping in the code generator (some risk
// architectures have big and little endian loads and stores).
//
// Terminology:
//   Big endian      0x4142434445464748 stores as "ABCDEFGH"
//   Littlen endian  0x4142434445464748 stores as "HGFEDCBA"
//   Native Endian   The endianess supported by the target hardware
//   Program Endian  The endianess selected for the API.

// The way this work is the user give an option to the compiler specifying
// whether the want little endian or big endian semantics.
// The target specifies whether the hardware supports little endian,
// big endian (or both).

// The endian emulation pass will only operate

// The basic idea is that bswap operations are emitted for all memory
// EXCEPT locations for which no semantic difference will result if there
// is no bswap.  This means that we do NOT swap any first class parameters
// (by value parameters, that is) or first class return values.
// The LLVM IR happens to be very amenable to this transformation:
// In the LLVM environment, this means we only swap values loaded and
// stored via pointers - UNLESS the value pointed to cannot possibly be
// accessed with differing bit widths.

// The analysis for this pass is similar to alias analysis (and borrows from
// the BasicAliasAnalysis pass), but must take into account not only whether
// a set of accesses aliases, but the bit width of the first class type being
// accessed.  The goal is to be able to avoid swapping on the following
// iff there is no aliasing to different bit widths or other storage types:
//
//    o  Stack frame variables (alloca)
//    o  Internal static variables.
//    o  Simple structures passed as arguments to internal functions
//       (under the assumption that displays will be implemented
//       by passing a pointer to the display as a parameter).

// For efficiency, this pass should run after mem2reg (there will be
// less allocas and hence fewer memory accesses to evaluate).
// It should run before InstructionCombining pass.

#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/EndianEmulationUtils.h"
// #include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/IndexedMap.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/Pass.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"

using namespace llvm;

namespace llvm {

  const int AccessSizeMax = 128;
  const int AccessSizeMultiple = 255;
  const int AccessSizeDeleted = 254;
  typedef enum {unknownMatch, singleMatch, multipleMatch} RangeMatchType;
  
  typedef enum SwapRequirement {
    SwapCanBeOptimized,
    MustSwap,
    CannotSwap
  } SwapRequirement;

  enum ExtensionKind {
    EK_NotExtended,
    EK_SignExt,
    EK_ZeroExt
  };
  
  struct VariableGEPIndex {
    const Value *V;
    ExtensionKind Extension;
    int64_t Scale;
    uint64_t End;
    
    bool operator==(const VariableGEPIndex &Other) const {
      return V == Other.V && Extension == Other.Extension &&
      Scale == Other.Scale;
    }
    
    bool operator!=(const VariableGEPIndex &Other) const {
      return !(operator==(Other));
    }
  };
  
  class GepSummary
  {
  public:
    typedef int64_t gepOffsetType;
    GepSummary(){ offset = 0; }
    
  private:
    gepOffsetType offset;
    
  public:
    SmallVector<VariableGEPIndex, 4> varIndices;
    
    inline gepOffsetType GetOffset() const { return offset; };
    inline void AddOffset(gepOffsetType o) { offset += o; };
  };
  
  // Return value from GetBasedAccess
  class OneBasedAccess
  {
  public:
    Value *base;
    SwapRequirement swapReq;
    uint8_t fieldScalarSize;
    uint8_t fieldElementCount;
    GepSummary gep;

    OneBasedAccess()
    { base = NULL; swapReq = SwapCanBeOptimized; fieldScalarSize = 0; fieldElementCount = 1; }
    
    OneBasedAccess(Value *b, SwapRequirement mustSwap, const DataLayout *TD, Type *elementType)
    {
      base = b;
      swapReq = mustSwap;
      if (VectorType *VT = dyn_cast<VectorType>(elementType))
      {
        fieldScalarSize = TD->getTypeStoreSize(VT->getVectorElementType());
        fieldElementCount = VT->getVectorNumElements();
      }
      else
      {
        fieldScalarSize = TD->getTypeStoreSize(elementType);
        fieldElementCount = 1;
      }
    }
  };
  
  class FieldOffsetMap {
  private:
    const static int PreallocatedRanges = 1;
    typedef
    struct OffsetDesc {
      uint64_t Offset;  // offset within base storage.
      uint64_t EndOffset;
      uint64_t ElementSize;
      uint64_t AccessSize: 8;
      uint64_t AccessScale: 56;
    } OffsetRange;

    int32_t NumRanges;
    int32_t MaxRanges;
    OffsetRange *Ranges;
    OffsetRange SomeRanges[PreallocatedRanges];
    
  public:
     FieldOffsetMap()
    { NumRanges = 0; MaxRanges = PreallocatedRanges; Ranges = SomeRanges; }
    ~FieldOffsetMap() { if (Ranges != SomeRanges) delete [] Ranges; }
    
    void InsertField(const OneBasedAccess *ref, bool invalid,
                     Value *sizeArg);
    bool FieldMatches(const OneBasedAccess *ref, Type *elementType);

  private:
    void InsertIndexRange(uint64_t offset, uint8_t scalerSize,
                          uint64_t elementSize, ExtensionKind Extension,
                          uint64_t Scale, uint64_t End);
    RangeMatchType IndexRangeMatches(uint64_t offset, uint8_t accessSize,
                           uint64_t elementSize, ExtensionKind extension,
                           uint64_t scale, uint64_t end);
    int32_t FindRange(uint64_t offset);
    void InsertRange(OffsetRange &r);
    void DeleteRange(int32_t ix) { Ranges[ix].AccessSize = AccessSizeDeleted; }
  };
  
  /// EndianEmulation Pass - Implement endian API by inserting bswap
  /// instructions.
  class EndianEmulation : public ModulePass {
  public:
    EndianEmulation(Endianness whichEndian, char &ID) : ModulePass(ID)
    {
      targetEndianess = AnyEndianness;
      apiEndianess = whichEndian;
      Optimize = true;
    }
    virtual ~EndianEmulation() {}
    virtual bool runOnModule(Module &M);
    virtual bool doInitialization(Module &) = 0;
    bool runOnFunction(Function &F);
    bool doFinalization(Module &);

  private:
    class BaseUsage
    {
    public:
      BaseUsage() {swapReq = SwapCanBeOptimized; fieldMap = NULL; }
      ~BaseUsage() { if (fieldMap) delete fieldMap; }
      
      SwapRequirement swapReq;
      FieldOffsetMap *fieldMap;
    };
    
    // Return value from GetBasedAccess
    class BasedAccess
    {
    public:
      ~BasedAccess() {keys.clear();}
      
      SmallVector<OneBasedAccess, 5> keys;
    };
    
    class gbaRecursionMarker
    {
    public:
      gbaRecursionMarker *next;
      const Value *beingProcessed;
      GepSummary gep;
      gbaRecursionMarker() {next = NULL; beingProcessed = NULL; }
    };
    
    Endianness targetEndianess;
    Endianness apiEndianess;
    Module * Mod;
    const DataLayout *TD;
    bool Optimize;
    DenseMap<Value *, BaseUsage> baseMap;
    SmallVector<BasicBlock *, 500> BL;

  public:
    Module *getModule() { return Mod; }

    bool argAndPointerMatch(const Value *arg, Value *argPointer);
    void CheckArgForPointer(Function *func, int argNo, Value *operand);
    void CheckForPointerStore(Value *operand);
    void CheckPointerStore(Function *func, Value *operand, uint32_t argNo);
    void AliasGlobalVariable(GlobalValue *GV);
    void MergeSwapRequirements(SwapRequirement &firstReq,
                               const Value *&firstV,
                               SwapRequirement thisReq,
                               const Value *thisV);
    void ClassifyValueAccess(const Instruction *I, Value *argPointer,
                             Value *sizeArg);
    void ClassifyValueAccess(const Instruction *I, Value *argPointer)
    {
      ClassifyValueAccess(I, argPointer, nullptr);
    }
    void ClassifyFirstClassInitialization(GlobalVariable* GV, Constant *CC,
                                          uint64_t offset,
                                          SwapRequirement forceSwap);
    bool recursiveGetBasedAccessCall(gbaRecursionMarker *recursions,
                                    const Value *V);
    bool GetBasedAccessInt(Value *operand, gbaRecursionMarker *recursions,
                        BasedAccess &rets);
    bool GetBasedAccess(Value *operand, BasedAccess &rets);
    enum SwapRequirement baseMustSwap(const Value *base);
    bool ConstantMustSwap(GlobalVariable* GV, uint64_t offset, Constant *I);
    bool SwapNeeded(const Instruction *I, Value *pointerArg);
    bool SwapArg(Instruction *IN, Value *pointerArg, int argNo);
    bool SwapResult(Instruction *IN, Value *pointerArg);
    bool SwapCmpXchgResult(Instruction *IN, Value *pointerArg);
    bool ExpandAtomicRMW(AtomicRMWInst *IN, Value *pointerArg, unsigned opcode,
                         CmpInst::Predicate pred);
  };

  class ConstantExprWalk {

  protected:
    Module * Mod;
    const DataLayout *TD;
    class EndianEmulation *EE;
    
  public:
    ConstantExprWalk(class EndianEmulation *EndianEmulationClass)
    { EE = EndianEmulationClass; Mod = EE->getModule(); Mod->getDataLayout(); }
    virtual ~ConstantExprWalk() {}
    
    Constant *WalkConstantExpr(GlobalVariable* GV, Constant *CC, uint64_t offset = 0);
    virtual void Visit(GlobalVariable* GV, Constant *CC, uint64_t offset) { }
    virtual Constant *VisitUnswappedTypes(GlobalVariable* GV, Constant *CC, uint64_t offset)
    { return CC; }
    virtual Constant *VisitSwappedTypes(GlobalVariable* GV, Constant *CC, uint64_t offset)
    { return CC; }

  private:
    Constant *WalkExtractValue(GlobalVariable* GV, ConstantExpr *CE, uint64_t offset);
  };

  class ClassifyInitializer : public ConstantExprWalk {
    
  public:
    ClassifyInitializer(class EndianEmulation *EndianEmulationClass)
    : ConstantExprWalk(EndianEmulationClass) {}
    
    virtual void Visit(GlobalVariable* GV, Constant *CC, uint64_t offset);
    virtual Constant *VisitUnswappedTypes(GlobalVariable* GV,
                                        Constant *CC, uint64_t offset);
    virtual Constant *VisitSwappedTypes(GlobalVariable* GV,
                                        Constant *CC, uint64_t offset);
  };
  
  class SwapInitializer : public ConstantExprWalk {

  public:
    SwapInitializer(class EndianEmulation *EndianEmulationClass)
    : ConstantExprWalk(EndianEmulationClass) {}
    
    virtual Constant *VisitSwappedTypes(GlobalVariable* GV,
                                        Constant *CC, uint64_t offset);
  };
  
 class BigEndianEmulation : public EndianEmulation {
  public:
    static char ID; // Pass identification, replacement for typeid
    BigEndianEmulation() : EndianEmulation(BigEndian, ID) {
      initializeBigEndianEmulationPass(*PassRegistry::getPassRegistry());
    }
    virtual ~BigEndianEmulation() {}
    virtual bool doInitialization(Module &);
  };
  
  class LittleEndianEmulation : public EndianEmulation {
  public:
    static char ID; // Pass identification, replacement for typeid
    LittleEndianEmulation() : EndianEmulation(LittleEndian, ID) {
      initializeLittleEndianEmulationPass(*PassRegistry::getPassRegistry());
    }
    virtual ~LittleEndianEmulation() {}
    virtual bool doInitialization(Module &);
  };
}

// Publicly exposed interface to pass...
// The external ID is only need if another pass depends on this one.
// char &llvm::EndianEmulationID = EndianEmulation::ID;

char BigEndianEmulation::ID = 0;
INITIALIZE_PASS_BEGIN(BigEndianEmulation, "bigendian",
                "Present a big endian API", false, false)
// INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfo)
INITIALIZE_PASS_END(BigEndianEmulation, "bigendian",
                 "Present a big endian API", false, false)
// createEndianEmulationPass - Interface to this file...
ModulePass *llvm::createBigEndianEmulationPass()
{
  return new BigEndianEmulation();
}

char LittleEndianEmulation::ID = 0;
INITIALIZE_PASS_BEGIN(LittleEndianEmulation, "littleendian",
                      "Present a little endian API", false, false)
// INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfo)
INITIALIZE_PASS_END(LittleEndianEmulation, "littleendian",
                    "Present a little endian API", false, false)
ModulePass *llvm::createLittleEndianEmulationPass()
{
  return new LittleEndianEmulation();
}

bool
BigEndianEmulation::doInitialization(Module &M)
{
  M.addModuleFlag(Module::Error, "endian-emulation", BigEndian);
  return false;
}

bool
LittleEndianEmulation::doInitialization(Module &M)
{
  M.addModuleFlag(Module::Error, "endian-emulation", LittleEndian);
  return false;
}

bool
EndianEmulation::runOnModule(Module &M)
{
  bool Changed = doInitialization(M);
  
  TD = &M.getDataLayout();
  targetEndianess = (TD->isLittleEndian())
                  ? !(TD->isBigEndian()) ? LittleEndian : AnyEndianness
                  : (TD->isBigEndian()) ? BigEndian : AnyEndianness;

  // We know what the code generator supports, now reconcile
  // with what the user specified.
  if (ConstantInt *Val = mdconst::extract_or_null<ConstantInt>(
                                  M.getModuleFlag("endian-emulation")))
  {
    switch(Val->getZExtValue())
    {
      case BigEndian:
        apiEndianess = BigEndian;
        break;
        
      case LittleEndian:
        apiEndianess = LittleEndian;
        break;
        
      default:
        apiEndianess = targetEndianess;
    }
  }
  else
    apiEndianess = targetEndianess;

  if (apiEndianess == targetEndianess) // Already what user wants.
    return false;
  
  if (targetEndianess == AnyEndianness) // defer to Code Gen.
    return false;
  
  ClassifyInitializer ci(this);
  
  for (GlobalVariable &gv: M.globals())
  {
    if (!gv.hasInitializer())
      continue;
    
    // Swaps for initialization.
    ci.WalkConstantExpr(&gv, gv.getInitializer());
  }
  
  for (Module::iterator I = M.begin(), E = M.end(); I != E; ++I)
    Changed |= runOnFunction(*I);
  
  Changed |= doFinalization(M);
  
  return Changed;
}

// The runOnFunction pass is used to do initial analysis and build a list
// list of basic blocks to operate on after initial data gathering.
// The doFinalization pass does all the work.
bool EndianEmulation::runOnFunction(Function &F)
{
  // First, make a list of base pointers that are hopelessly aliased
  // (i.e., stored, passed to a function or accessed using different types.
  // Also, figure out which back blocks actually contain instructions we
  // care about (there is no sense in looking at the others more than once).
  
  for (Function::iterator I = F.begin(), E = F.end(); I != E; )
  {
    BasicBlock *bb = &*I++;
    bool useBB = false;
    
    for (BasicBlock::const_iterator II = bb->begin(), IE = bb->end(); II != IE; ++II)
    {
      const Instruction *I = &*IE;

      switch (I->getOpcode())
      {
        case Instruction::Load:
          assert(argAndPointerMatch(I, I->getOperand(0)) &&
                 "Incorrect types for .");
          ClassifyValueAccess(I, I->getOperand(0));
          useBB = true;
          break;
          
        case Instruction::Store:
          assert(argAndPointerMatch(I->getOperand(0), I->getOperand(1)) &&
                 "Incorrect types for store.");
          CheckForPointerStore(I->getOperand(0));
          ClassifyValueAccess(I, I->getOperand(1));
          useBB = true;
          break;
          
        case Instruction::AtomicCmpXchg:
        {
          assert(argAndPointerMatch(I->getOperand(2), I->getOperand(0)) &&
                 argAndPointerMatch(I->getOperand(1), I->getOperand(0)) &&
                 "Incorrect types for cmpxchg.");
          const AtomicCmpXchgInst *XI = dyn_cast<AtomicCmpXchgInst>(I);
          CheckForPointerStore(XI->getOperand(2));
          ClassifyValueAccess(I, I->getOperand(0));
          useBB = true;
          break;
        }
          break;
          
        case Instruction::AtomicRMW:
        {
          assert(argAndPointerMatch(I->getOperand(1), I->getOperand(0)) &&
                 "Incorrect types for atomicrmw.");
          const AtomicRMWInst *RMWI = dyn_cast<AtomicRMWInst>(I);
          CheckForPointerStore(RMWI->getOperand(1));
          ClassifyValueAccess(I, I->getOperand(0));
          useBB = true;
          break;
        }
          break;
          
        case Instruction::Ret:
          if (I->getNumOperands())
          {
            // Check for local functions?
            CheckForPointerStore(I->getOperand(0));
          }
         break;

        case Instruction::Call:
          if (const IntrinsicInst *II = dyn_cast<IntrinsicInst>(I))
          {
            switch (II->getIntrinsicID())
            {
              case Intrinsic::memcpy:
              case Intrinsic::memmove:
                ClassifyValueAccess(I, I->getOperand(0), I->getOperand(2));
                ClassifyValueAccess(I, I->getOperand(1), I->getOperand(2));
                break;
                
              case Intrinsic::gcroot:
                useBB = true;
                break;
              case Intrinsic::gcread:
                assert(argAndPointerMatch(I, I->getOperand(1)) &&
                       "Incorrect types for gcread.");
                ClassifyValueAccess(I, I->getOperand(1));
                useBB = true;
                break;
              case Intrinsic::gcwrite:
                assert(argAndPointerMatch(I->getOperand(0), I->getOperand(2)) &&
                       "Incorrect types for gcwrite.");
                CheckForPointerStore(I->getOperand(0));
                ClassifyValueAccess(I, I->getOperand(2));
                useBB = true;
                break;
                
              default:;
            }
          }
          else
          {
            const CallInst *CI = dyn_cast<CallInst>(I);
            int numArgs = CI->getNumArgOperands();
            for(int argno = 0; argno < numArgs; argno++)
            {
              CheckArgForPointer(CI->getCalledFunction(), argno,
                                 CI->getArgOperand(argno));
            }
          }
          break;

        case Instruction::Invoke:
        {
          const InvokeInst *II = dyn_cast<InvokeInst>(I);
          int numArgs = II->getNumArgOperands();
          for(int argno = 0; argno < numArgs; argno++)
          {
            CheckArgForPointer(II->getCalledFunction(), argno,
                               II->getArgOperand(argno));
          }
          break;
        }

        default:;
      }
    }

    if (useBB)
      BL.push_back(bb);
  }

  return false;
}

// The finalization does all the real work of inserting bswaps.
bool
EndianEmulation::doFinalization(Module &M)
{
  bool Changed = false;
  
  if (apiEndianess == targetEndianess) // Already what user wants.
    return false;
  
  if (targetEndianess == AnyEndianness) // defer to Code Gen.
    return false;

  SwapInitializer si(this);
  
  for (GlobalVariable &gv: M.globals())
  {
    if (!gv.hasInitializer())
      continue;
    
    // Swaps for initialization.
    Constant *C = gv.getInitializer();
    Constant *newC = si.WalkConstantExpr(&gv, C);
    if (newC && newC != C)
    {
      gv.setInitializer(newC);
      Changed = true;
    }
  }
  
  for (SmallVector<BasicBlock *, 500>::iterator I = BL.begin(), E = BL.end();
       I != E; I++)
  {
    BasicBlock *Cur = *I; // Advance over block so we don't traverse new blocks
    SmallVector<Instruction*, 500> IL;

    // Make a list of the instructions, because we are going to be adding some
    // and splitting the basic block (it's a waste of time to visit the new
    // instructions and we also may split of the basic block, but still want to
    // visit all the original instructions.
    for(BasicBlock::iterator J = Cur->begin(), IE = Cur->end();
        J != IE; J++)
      IL.push_back(&*J);

    // The basic block can be split after this; so, don't trust "Cur" beyond
    // this point!

    // Process all the instructions in this basic block.
    for(SmallVector<Instruction *, 500>::iterator J = IL.begin(), IE = IL.end();
        J != IE; J++)
    {
      Instruction *IN = *J;
      Value *pointerArg = NULL;
      
      switch (IN->getOpcode())
      {
        case Instruction::Load:
          pointerArg = IN->getOperand(0);
          Changed |= SwapResult(IN, pointerArg);
          break;
          
        case Instruction::Store:
          pointerArg = IN->getOperand(1);
          Changed |= SwapArg(IN, pointerArg, 0);
          break;

        case Instruction::Call:
          if (IntrinsicInst *II = dyn_cast<IntrinsicInst>(IN))
          {
            switch (II->getIntrinsicID())
            {
                // The garbage collection intrinsics may not have the correct
                // type associated with the pointer (the documentation gives
                // i8**, but I think it means any pointer type).  This may need
                // additional work to allow endianess to be specified for
                // individual objects.
              case Intrinsic::gcroot:
                break;
              case Intrinsic::gcread:
                pointerArg = IN->getOperand(2);
                Changed |= SwapResult(IN, pointerArg);
                break;
              case Intrinsic::gcwrite:
                pointerArg = IN->getOperand(3);
                Changed |= SwapArg(IN, pointerArg, 1);
                break;
                
              default:;
            }
          }
          break;

        case Instruction::AtomicCmpXchg:
          pointerArg = IN->getOperand(0);
          Changed |= SwapArg(IN, pointerArg, 1);
          Changed |= SwapArg(IN, pointerArg, 2);
          Changed |= SwapCmpXchgResult(IN, pointerArg);
          break;

        case Instruction::AtomicRMW:
          pointerArg = IN->getOperand(0);
          AtomicRMWInst *rmwi = cast<AtomicRMWInst>(IN);
          AtomicRMWInst::BinOp operation = rmwi->getOperation();
          switch(operation)
          {
            case AtomicRMWInst::Xchg:
            case AtomicRMWInst::And:
            case AtomicRMWInst::Nand:
            case AtomicRMWInst::Or:
            case AtomicRMWInst::Xor:
              Changed |= SwapArg(IN, pointerArg, 1);
              Changed |= SwapResult(IN, pointerArg);
              break;
              
            case AtomicRMWInst::Add:
              Changed |= ExpandAtomicRMW(rmwi, pointerArg,
                                         Instruction::Add,
                                         ICmpInst::ICMP_EQ);
              break;
              
            case AtomicRMWInst::Sub:
              Changed |= ExpandAtomicRMW(rmwi, pointerArg,
                                         Instruction::Sub,
                                         ICmpInst::ICMP_EQ);
              break;
              
            case AtomicRMWInst::Max:
              Changed |= ExpandAtomicRMW(rmwi, pointerArg,
                                         Instruction::ICmp,
                                         ICmpInst::ICMP_SGT);
              break;
              
            case AtomicRMWInst::Min:
              Changed |= ExpandAtomicRMW(rmwi, pointerArg,
                                         Instruction::ICmp,
                                         ICmpInst::ICMP_SLT);
              break;
              
            case AtomicRMWInst::UMax:
              Changed |= ExpandAtomicRMW(rmwi, pointerArg,
                                         Instruction::ICmp,
                                         ICmpInst::ICMP_UGT);
              break;
              
            case AtomicRMWInst::UMin:
              Changed |= ExpandAtomicRMW(rmwi, pointerArg,
                                         Instruction::ICmp,
                                         ICmpInst::ICMP_ULT);
              break;
              
            default:
              assert(false && "Unexpected atomic intrinsic type.")
              ;
          }
          break;
       }
    }
  }

  BL.clear();  // Don't need these any more.
  baseMap.clear();
  
  return Changed;
}

Constant *
ConstantExprWalk::WalkConstantExpr(GlobalVariable* GV, Constant *CC, uint64_t offset)
{
  Constant *newCC = nullptr;
  
  // Swapping zero values is a noop, this is easy.
  if (isa<ConstantAggregateZero>(CC) ||
      isa<ConstantPointerNull>(CC) ||
      isa<UndefValue>(CC))
    return CC;
  
  if (const ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(CC))
  {
    ArrayRef<Constant *> Elts;
    bool Changed = false;
    SequentialType *ST = CDS->getType();
    uint64_t elementSize = TD->getTypeAllocSize(ST->getElementType());
    
    for (uint64_t j = 0, e = CDS->getNumElements(); j != e; ++j)
    {
      Constant *C = CDS->getElementAsConstant(j);
      Constant *newC = WalkConstantExpr(GV, C, offset);
      if (newC && newC != C)
      {
        Changed = true;
        Elts.vec().push_back(newC);
      }
      else
        Elts.vec().push_back(C);
      
      offset += elementSize;
    }
    
    if (Changed)
      if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(CC))
        newCC = ConstantArray::get(CDA->getType(), Elts);
      else
        newCC = ConstantVector::get(Elts);
    else
      newCC = CC;
  }
  else if (const ConstantArray *CVA = dyn_cast<ConstantArray>(CC))
  {
    ArrayRef<Constant *> Elts;
    bool Changed = false;
    ArrayType *AT = CVA->getType();
    uint64_t elementSize = TD->getTypeAllocSize(AT->getElementType());
    
    for (uint64_t j = 0, e = CVA->getNumOperands(); j != e; ++j)
    {
      Constant *C = CVA->getOperand(j);
      Constant *newC = WalkConstantExpr(GV, C, offset);
      if (newC && newC != C)
      {
        Changed = true;
        Elts.vec().push_back(newC);
      }
      else
        Elts.vec().push_back(C);
      
      offset += elementSize;
    }
    
    if (Changed)
      newCC = ConstantArray::get(AT, Elts);
    else
      newCC = CC;
  }
  else if (const ConstantVector *CVV = dyn_cast<ConstantVector>(CC))
  {
    ArrayRef<Constant *> Elts;
    bool Changed = false;
    VectorType *VT = CVV->getType();
    uint64_t elementSize = TD->getTypeAllocSize(VT->getElementType());
    
    for (uint64_t j = 0, e = CVV->getNumOperands(); j != e; ++j)
    {
      Constant *C = CVV->getOperand(j);
      Constant *newC = WalkConstantExpr(GV, C, offset);
      if (newC && newC != C)
      {
        Changed = true;
        Elts.vec().push_back(newC);
      }
      else
        Elts.vec().push_back(C);
      
      offset += elementSize;
    }
    
    if (Changed)
      newCC = ConstantVector::get(Elts);
    else
      newCC = CC;
  }
  else if (const ConstantStruct *CVS = dyn_cast<ConstantStruct>(CC))
  {
    uint64_t num = CVS->getNumOperands();
    ArrayRef<Constant *> Elts;
    bool Changed = false;
    
    for (uint64_t j = 0; j < num; j++)
    {
      Constant *C = CVS->getOperand(j);
      Constant *newC = WalkConstantExpr(GV, C, offset);
      if (newC && newC != C)
      {
        Changed = true;
        Elts.vec().push_back(newC);
      }
      else
        Elts.vec().push_back(C);
      
      offset += TD->getTypeAllocSize(C->getType());
    }
    
    if (Changed)
      newCC = ConstantStruct::get(CVS->getType(), Elts);
    else
      newCC = CC;
  }
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(CC))
  {
    switch (CE->getOpcode())
    {
      case Instruction::ExtractValue:
      {
        Constant *newC = WalkExtractValue(GV, CE, offset);
        if (newC)
        {
          newCC = newC;
          break;
        }
      }
        
      default:
        assert(false && "Unexpected ConstantExpr.");
    }
  }
  else
  {
    // BlockAddress, ConstantExpr, ConstantFP,
    // ConstantInt or GlobalValue.
    
    Visit(GV, CC, offset);
    
    Type *T = CC->getType();
    Type *ST = T->getScalarType();

    switch(ST->getTypeID())
    {
      case Type::HalfTyID:
      case Type::X86_FP80TyID:
      case Type::FP128TyID:
      case Type::PPC_FP128TyID:
      case Type::MetadataTyID:
      case Type::X86_MMXTyID:
        // We don't swap these.
        newCC = VisitUnswappedTypes(GV, CC, offset);
        break;
        
      case Type::IntegerTyID:
      case Type::FloatTyID:
      case Type::DoubleTyID:
      case Type::FunctionTyID:
      case Type::LabelTyID:
      case Type::VectorTyID:
      case Type::PointerTyID:
        newCC = VisitSwappedTypes(GV, CC, offset);
        break;
        
      case Type::StructTyID:
      case Type::ArrayTyID:
      default:
        assert(false && "Unexpected type encoding.");
        // These aren't supposed to happen, return NULL.
        break;
    }
  }
  
  assert(newCC && "Unexpected initialization construct.");
  return newCC;
}

Constant *
ConstantExprWalk::WalkExtractValue(GlobalVariable* GV, ConstantExpr *CE, uint64_t offset)
{
  ArrayRef<unsigned>EI = CE->getIndices();
  Constant *CC = CE->getOperand(0);

  for( ArrayRef<unsigned>::iterator currentIx = EI.begin(), endIx = EI.end();
      currentIx != endIx; )
  {
    unsigned index = *currentIx;
    
    // Swapping zero values is a noop, this is easy.
    if (isa<ConstantAggregateZero>(CC))
      return CE;
    
    if (const ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(CC))
    {
      // Anything out of bounds is zero:  Ignore it.
      if (index >= CDS->getNumOperands())
        return CE;

      CC = CDS->getElementAsConstant(index);
      currentIx++;
    }
    else if (const ConstantArray *CVA = dyn_cast<ConstantArray>(CC))
    {
      // Anything out of bounds is zero:  Ignore it.
      if (index >= CVA->getNumOperands())
        return CE;
      
      CC = CVA->getOperand(index);
      currentIx++;
    }
    else if (const ConstantStruct *CVS = dyn_cast<ConstantStruct>(CC))
    {
      // Anything out of bounds is zero:  Ignore it.
      if (index >= CVS->getNumOperands())
        return CE;
      
      CC = CVS->getOperand(index);
      currentIx++;
    }
    else if (ConstantExpr *CE2 = dyn_cast<ConstantExpr>(CC))
    {
      if (CE2->getOpcode() == Instruction::InsertValue)
      {
        ArrayRef<unsigned>II = CE2->getIndices();
        ArrayRef<unsigned>::iterator EB = currentIx;
        ArrayRef<unsigned>::iterator IB = II.begin();
        ArrayRef<unsigned>::iterator IE = II.end();
        bool matched = true;
        
        for(ArrayRef<unsigned>::iterator I = IB; I != IE; EB++, I++)
        {
          if (EB == endIx)
            break;
          
          if (*EB != *I)
          {
            matched = false;
            break;
          }
        }
        
        // If we are extracting the value we are inserting, we must use the
        // new value and skip ahead over the indices that matched;
        // otherwise, this is a noop (don't advance to next index).
        
        if (matched)
        {
          CC = CE2->getOperand(1);
          currentIx = EB;
        }
        else
        {
          CC = CE2->getOperand(0);
        }
      }
    }
    else
    {
      return nullptr;
    }
  }

  Constant *newCC = WalkConstantExpr(GV, CC, offset);

  // If the value changed, we just return the new extracted expression;
  // otherwise, we return the orignal expression unchanged.
  return (newCC != CC) ? newCC : CE;
}

void
ClassifyInitializer::Visit(GlobalVariable* GV, Constant *CC,
                                     uint64_t offset)
{
  // Mark any external references as aliased bases.
  // We are assuming that none of the special llvm variables
  // are referenced from other special llvm variables.
  // If that ever changes, we need to check the name here
  // and pick CannotSwap for the special variables.
  if (GlobalValue *GVRef = dyn_cast<GlobalValue>(CC))
  {
    EE->AliasGlobalVariable(GVRef);
    EE->ClassifyFirstClassInitialization(GV, CC, offset, MustSwap);
  }
}

Constant *
ClassifyInitializer::VisitUnswappedTypes(GlobalVariable* GV, Constant *CC,
                                         uint64_t offset)
{
  // Mark as unoptimizable.
  EE->ClassifyFirstClassInitialization(GV, CC, offset, CannotSwap);
  return CC;
}

Constant *
ClassifyInitializer::VisitSwappedTypes(GlobalVariable* GV, Constant *CC,
                                       uint64_t offset)
{
  // Record the access granularity.
  EE->ClassifyFirstClassInitialization(GV, CC, offset, SwapCanBeOptimized);
  return CC;
}

Constant *
SwapInitializer::VisitSwappedTypes(GlobalVariable* GV,
                           Constant *CC, uint64_t offset)
{
  if (!EE->ConstantMustSwap(GV, offset, CC))
    // Not required to swap this.
    return CC;

  Constant *newCC = CC;

  if (ConstantInt *CI = dyn_cast<ConstantInt>(CC))
  {
    APInt val = CI->getValue();
    newCC = ConstantInt::get(CI->getType(), val.byteSwap());
  }
  else if (ConstantFP *CF = dyn_cast<ConstantFP>(CC))
  {
    APFloat val = CF->getValueAPF();
    val.invertBswap();
    newCC = ConstantFP::get(Mod->getContext(), val);
  }
//  else if (GlobalBswap *GBS = dyn_cast<GlobalBswap>(CC))
//  {
//   newCC = GBS->getOperand(0);
//  }
//  else if (GlobalValue *GV = dyn_cast<GlobalValue>(CC))
//  {
//    newCC = GlobalBswap::create(Mod->getContext(), GV);
//  }
  else
  {
      newCC = ConstantExpr::getBswapOfFirstClassType(TD, CC);
  }
  return newCC;
}

// Verify that an argument and the pointer to actually have the same type.
bool EndianEmulation::argAndPointerMatch(const Value *arg, Value *argPointer)
{
  Type *pt = dyn_cast<PointerType>(argPointer->getType());
  
  return pt && arg->getType() == pt->getScalarType();
}

void
EndianEmulation::CheckArgForPointer(Function *func, int argNo, Value *operand)
{
  if (isa<PointerType>(operand->getType()))
  {
    CheckPointerStore(func, operand, argNo);
  }
}

void
EndianEmulation::CheckForPointerStore(Value *operand)
{
  if (isa<PointerType>(operand->getType()))
  {
    CheckPointerStore(NULL, operand, -1);
  }
}

/// Diagnostic information for inline asm reporting.
/// This is basically a message and an optional location.
class DiagnosticInfoEndianEmulation : public DiagnosticInfo {
private:
  /// Message to be reported.
  const Twine &MsgStr;
  const Value *arg1;
  const Value *arg2;
  
public:
  /// \p MsgStr is the message to be reported to the frontend.
  /// This class does not copy \p MsgStr, therefore the reference must be valid
  /// for the whole life time of the Diagnostic.
  DiagnosticInfoEndianEmulation(const Twine &MsgStr, const Value *V1,
                                const Value *V2,
                                DiagnosticSeverity Severity = DS_Error)
  : DiagnosticInfo(DK_EndianEmulation, Severity), MsgStr(MsgStr),
  arg1(V1), arg2(V2) {}
  
  const Twine &getMsgStr() const { return MsgStr; }
  const Value * getArg1() const { return arg1; }
  const Value * getArg2() const { return arg2; }
 
  /// \see DiagnosticInfo::print.
  void print(DiagnosticPrinter &DP) const override;
  
  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_EndianEmulation;
  }

private:
  void printEmulationValue(DiagnosticPrinter &DP, const Value *V) const;
};

void
DiagnosticInfoEndianEmulation::
printEmulationValue(DiagnosticPrinter &DP, const Value *V) const {

  unsigned LocCookie = 0;
  if (const Instruction *I = dyn_cast<Instruction>(V)) {
    if (const MDNode *SrcLoc = I->getMetadata("srcloc")) {
      if (SrcLoc->getNumOperands() != 0)
        if (const auto *CI =
            mdconst::dyn_extract<ConstantInt>(SrcLoc->getOperand(0))) {
          LocCookie = CI->getZExtValue();
        }
    }
  }
  if (LocCookie)
    DP << " at line " << LocCookie;
  else
    DP << " with " << V->getName();
}

void DiagnosticInfoEndianEmulation::print(DiagnosticPrinter &DP) const {
  DP << getMsgStr();
  printEmulationValue(DP, getArg1());
  DP << " and " ;
  printEmulationValue(DP, getArg2());
}



void
EndianEmulation::MergeSwapRequirements(SwapRequirement &firstReq, const Value *&firstV,
                      SwapRequirement thisReq, const Value *thisV)
{
  if (thisReq == SwapCanBeOptimized)
    return;
  
  if (thisReq != firstReq)
  {
    LLVMContext &Ctx = Mod->getContext();
    class DiagnosticInfoEndianEmulation DI(
                        "Aliases imply mixed endian emulation ",
                        firstV, thisV, DS_Error);
    Ctx.diagnose(DI);
    return;
  }
  
  firstReq = thisReq;
  firstV = thisV;
}

void
EndianEmulation::ClassifyValueAccess(const Instruction *IN, Value *pointerArg,
                                     Value *sizeArg)
{
  assert(isa<PointerType>(pointerArg->getType()) && "arg is not pointer type");

  if (!Optimize)
    return;
  
  PointerType *pt = dyn_cast<PointerType>(pointerArg->getType());
  Type *t = pt->getElementType();
  Endianness desired = ComputeEndianAccessType(IN, t, apiEndianess, targetEndianess);
  
  BasedAccess bases;
  GetBasedAccess(pointerArg, bases);

  SwapRequirement mergeReq = SwapCanBeOptimized;
  const Value *firstV = nullptr;

  SmallVectorImpl<OneBasedAccess>::const_iterator E = bases.keys.end();
  for (SmallVectorImpl<OneBasedAccess>::const_iterator J = bases.keys.begin();
       J != E; J++)
  {
    const OneBasedAccess *ref = J;
 
    MergeSwapRequirements(mergeReq, firstV, baseMustSwap(ref->base), ref->base);
    
    // Otherwise, we need to look it up.
    std::pair<Value *, BaseUsage> bu;
    DenseMap<Value *, BaseUsage>::const_iterator B = baseMap.find(ref->base);
    if (B != baseMap.end())
    {
      bu = *B;
      
      MergeSwapRequirements(mergeReq, firstV, bu.second.swapReq, bu.first);
    }
  }

  // If the hardware does what we want it to, no swap is needed,
  // but we still need to register the access for aliasing purposes.
  if (desired == targetEndianess && mergeReq == SwapCanBeOptimized)
    mergeReq = MustSwap;
  
  for (SmallVectorImpl<OneBasedAccess>::const_iterator J = bases.keys.begin();
       J != E; J++)
  {
    const OneBasedAccess *ref = J;

    // If we always swap, we're done.
    if (baseMustSwap(ref->base) != SwapCanBeOptimized)
      continue;

    // Otherwise, we need to look it up.
    DenseMap<Value *, BaseUsage>::iterator B = baseMap.find(ref->base);
    if (B != baseMap.end())
    {
      // If this accesss always swaps, there is nothing to do here.
      if (B->second.swapReq != SwapCanBeOptimized)
        continue;

      B->second.swapReq = mergeReq;

      // If the merged accesss always swaps, there is also nothing to do.
      if (mergeReq != SwapCanBeOptimized)
        continue;
      
      // Otherwise, add the field map if it's not already there.
      // note that there is no way to update the map; so, we need
      // to delete and re-insert.
      if (!B->second.fieldMap)
        B->second.fieldMap = new FieldOffsetMap;

      B->second.fieldMap->InsertField(ref, mergeReq, sizeArg);
    }
    else
    {
      std::pair<Value *, BaseUsage> bu;
      bu.first = ref->base;
      bu.second.swapReq = mergeReq;
      bu.second.fieldMap = new FieldOffsetMap;
      baseMap.insert(bu);

      if (mergeReq == SwapCanBeOptimized)
        bu.second.fieldMap->InsertField(ref, mergeReq, sizeArg);
    }
  }
}

void
EndianEmulation::ClassifyFirstClassInitialization(GlobalVariable* GV, Constant *CC,
                                      uint64_t offset, SwapRequirement forceSwap)
{
  if (!Optimize)
    return;
  
  Type *T = CC->getType();
  
  Endianness desired = ComputeEndianAccessType(CC, T, apiEndianess,
                                               targetEndianess);

  SwapRequirement mergeReq = baseMustSwap(GV);
  const Value *firstV = GV;

  MergeSwapRequirements(mergeReq, firstV, forceSwap, CC);

  // If we always swap, we're done.
  if (mergeReq != SwapCanBeOptimized)
    return;
  
  // If the hardware does what we want it to, no swap is needed,
  // but we still need to register the access for aliasing purposes.
  if (desired == targetEndianess && mergeReq == SwapCanBeOptimized)
    mergeReq = MustSwap;
  
  OneBasedAccess ref(GV, mergeReq, TD, T);

  // Otherwise, we need to look it up.
  DenseMap<Value *, BaseUsage>::iterator B = baseMap.find(GV);
  if (B != baseMap.end())
  {
    MergeSwapRequirements(mergeReq, firstV, B->second.swapReq, B->first);

    // If this base always swaps, there is nothing to do here.
    if (B->second.swapReq != SwapCanBeOptimized)
      return;
    
    B->second.swapReq = mergeReq;

    // Likewise, if the merged result always swaps, we're done.
    if (mergeReq == SwapCanBeOptimized)
    {
      // Otherwise, add the field map if it's not already there.
      // note that there is no way to update the map; so, we need
      // to delete and re-insert.
      if (!B->second.fieldMap)
        B->second.fieldMap = new FieldOffsetMap;
      
      B->second.fieldMap->InsertField(&ref, mergeReq, nullptr);
    }
  }
  else
  {
    std::pair<Value *, BaseUsage> bu;
    bu.first = ref.base;
    bu.second.swapReq = mergeReq;
    bu.second.fieldMap = new FieldOffsetMap;
    baseMap.insert(bu);
    
    if (mergeReq == SwapCanBeOptimized)
      bu.second.fieldMap->InsertField(&ref, mergeReq, nullptr);
  }
}

void
EndianEmulation::CheckPointerStore(Function *func, Value *operand,
                                   uint32_t argNo)
{
  assert(isa<PointerType>(operand->getType()) && "arg is not pointer type");
  BasedAccess bases;
  if (!GetBasedAccess(operand, bases))
    return;

  SmallVectorImpl<OneBasedAccess>::const_iterator E = bases.keys.end();
  for (SmallVectorImpl<OneBasedAccess>::const_iterator J = bases.keys.begin();
       J != E; J++)
  {
    const OneBasedAccess *ref = J;
    
    // There is no point in keeping track of cases where we always swap.
    if (baseMustSwap(ref->base) != SwapCanBeOptimized)
      continue;

    if (func && func->hasLocalLinkage())
    {
      bool canExpand = true;

      // Loop through all the uses of the function to make sure they
      // are all calls and that this operand is passed.
      for (User::const_op_iterator J = func->op_begin(),
           E = func->op_end(); J != E && canExpand; J++)
      {
        const Use *U = J;
        const User *UV = U->getUser();
        const CallInst *CI = dyn_cast<CallInst>(UV);
        if (!CI)
          canExpand = false;
        else if (CI->getNumArgOperands() <= argNo)
          canExpand = false;
      }

      // This pointer will be tracked at all the call sites by
      // GetBasedAccessInt; so, it doesn't have to be noted here.
      if (canExpand)
        continue;
    }
    
    // In all other cases, we must mark the entire base as must swap.
    std::pair<Value *, BaseUsage> bu;
    DenseMap<Value *, BaseUsage>::iterator B = baseMap.find(ref->base);
    if (B != baseMap.end())
    {
      bu = *B;
      if (bu.second.swapReq != CannotSwap)
        continue;

      baseMap.erase(B);
    }

    bu.first = ref->base;
    bu.second.swapReq = MustSwap;
    bu.second.fieldMap = NULL;
    baseMap.insert(bu);
  }
}

void
EndianEmulation::AliasGlobalVariable(GlobalValue *GV)
{
  std::pair<Value *, BaseUsage> bu;
  DenseMap<Value *, BaseUsage>::iterator B = baseMap.find(GV);
  if (B != baseMap.end())
  {
    bu = *B;
    if (bu.second.swapReq != SwapCanBeOptimized)
      return;
    
    baseMap.erase(B);
  }
  
  bu.first = GV;
  bu.second.swapReq = MustSwap;
  bu.second.fieldMap = NULL;
  baseMap.insert(bu);
}

bool
EndianEmulation::SwapNeeded(const Instruction *IN, Value *pointerArg)
{
  PointerType *pt = dyn_cast<PointerType>(pointerArg->getType());
  if (!pt)
    return false;

  if (!Optimize)
    return true;

  Type *t = pt->getElementType();
  Endianness desired = ComputeEndianAccessType(IN, t, apiEndianess,
                                                       targetEndianess);
  // If the hardware does what we want it to, no swap is needed.
  if (desired == targetEndianess)
    return false;
  
  BasedAccess bases;
  GetBasedAccess(pointerArg, bases);
  
  bool mustSwap = false;
  
  SmallVectorImpl<OneBasedAccess>::const_iterator E = bases.keys.end();
  for (SmallVectorImpl<OneBasedAccess>::const_iterator J = bases.keys.begin();
       J != E && !mustSwap; J++)
  {
    const OneBasedAccess *ref = J;
    
    // If we always swap, we're done.
    if (baseMustSwap(ref->base))
    {
      mustSwap = true;
      break;
    }

    // Otherwise, we need to look it up.
    DenseMap<Value *, BaseUsage>::iterator B = baseMap.find(ref->base);
    assert(B != baseMap.end() && "Base not in base map, but should be.");

    mustSwap |= !B->second.fieldMap->FieldMatches(ref, t);
  }

  return mustSwap;
}

bool
EndianEmulation::ConstantMustSwap(GlobalVariable* GV, uint64_t offset,
                                  Constant *CC)
{
  if (!Optimize)
    return true;
  
  Type *T = CC->getType();

  Endianness desired = ComputeEndianAccessType(CC, T, apiEndianess,
                                               targetEndianess);
  // If the hardware does what we want it to, no swap is needed.
  if (desired == targetEndianess)
    return false;

  // If we always swap, we're done.
  if (baseMustSwap(GV))
    return true;

  // Otherwise, we need to look it up.
  DenseMap<Value *, BaseUsage>::iterator B = baseMap.find(GV);
  assert(B != baseMap.end() && "Base not in base map, but should be.");

  OneBasedAccess ref(GV, SwapCanBeOptimized, TD, T);

  return !B->second.fieldMap->FieldMatches(&ref, T);
}

// Check for recursive calls.
bool
EndianEmulation::recursiveGetBasedAccessCall(gbaRecursionMarker *recursions,
                                            const Value *V)
{
  for (gbaRecursionMarker *rm = recursions; rm; rm = rm->next)
  {
    // If we are already processing this argument, we don't need
    // to do anything.
    if (rm->beingProcessed == V)
      return true;
  }
  return false;
}

/// GetLinearExpression - Analyze the specified value as a linear expression:
/// "A*V + B", where A and B are constant integers.  Return the scale and offset
/// values as APInts and return V as a Value*, and return whether we looked
/// through any sign or zero extends.  The incoming Value is known to have
/// IntegerType and it may already be sign or zero extended.
///
/// Note that this looks through extends, so the high bits may not be
/// represented in the result.
static Value *GetLinearExpression(Value *V, APInt &Scale, APInt &Offset,
                                  ExtensionKind &Extension,
                                  const DataLayout &TD, unsigned Depth) {
  assert(V->getType()->isIntegerTy() && "Not an integer value");
  
  // Limit our recursion depth.
  if (Depth == 6) {
    Scale = 1;
    Offset = 0;
    return V;
  }
  
  if (BinaryOperator *BOp = dyn_cast<BinaryOperator>(V)) {
    if (ConstantInt *RHSC = dyn_cast<ConstantInt>(BOp->getOperand(1))) {
      switch (BOp->getOpcode()) {
        default: break;
        case Instruction::Or:
          // X|C == X+C if all the bits in C are unset in X.  Otherwise we can't
          // analyze it.
          if (!MaskedValueIsZero(BOp->getOperand(0), RHSC->getValue(), TD))
            break;
          // FALL THROUGH.
        case Instruction::Add:
          V = GetLinearExpression(BOp->getOperand(0), Scale, Offset, Extension,
                                  TD, Depth+1);
          Offset += RHSC->getValue();
          return V;
        case Instruction::Mul:
          V = GetLinearExpression(BOp->getOperand(0), Scale, Offset, Extension,
                                  TD, Depth+1);
          Offset *= RHSC->getValue();
          Scale *= RHSC->getValue();
          return V;
        case Instruction::Shl:
          V = GetLinearExpression(BOp->getOperand(0), Scale, Offset, Extension,
                                  TD, Depth+1);
          Offset <<= RHSC->getValue().getLimitedValue();
          Scale <<= RHSC->getValue().getLimitedValue();
          return V;
      }
    }
  }
  
  // Since GEP indices are sign extended anyway, we don't care about the high
  // bits of a sign or zero extended value - just scales and offsets.  The
  // extensions have to be consistent though.
  if ((isa<SExtInst>(V) && Extension != EK_ZeroExt) ||
      (isa<ZExtInst>(V) && Extension != EK_SignExt)) {
    Value *CastOp = cast<CastInst>(V)->getOperand(0);
    unsigned OldWidth = Scale.getBitWidth();
    unsigned SmallWidth = CastOp->getType()->getPrimitiveSizeInBits();
    Scale = Scale.trunc(SmallWidth);
    Offset = Offset.trunc(SmallWidth);
    Extension = isa<SExtInst>(V) ? EK_SignExt : EK_ZeroExt;
    
    Value *Result = GetLinearExpression(CastOp, Scale, Offset, Extension,
                                        TD, Depth+1);
    Scale = Scale.zext(OldWidth);
    Offset = Offset.zext(OldWidth);
    
    return Result;
  }
  
  Scale = 1;
  Offset = 0;
  return V;
}

bool
EndianEmulation::GetBasedAccessInt(Value *V, gbaRecursionMarker *recursions,
                                BasedAccess &rets)
{
  Type *pt = V->getType();
  Type *et = pt->getPointerElementType();
  assert(isa<PointerType>(pt) && "arg is not pointer type");
  gbaRecursionMarker rm;
  if (recursions) {
    rm.next = recursions;
    rm.gep = recursions->gep;
  }

  OneBasedAccess ret(nullptr, SwapCanBeOptimized, TD, et);
  
  // We evaluate the reference bottom up; so, we are seeing the lowest
  // level GEPs, first.
  for ( ;; ) {
    if (GEPOperator *GEPOp = dyn_cast<GEPOperator>(V))
    {
      V = GEPOp->getPointerOperand();

      if (!et->isSized())
        ret.swapReq = MustSwap;

      if (TD && ret.swapReq == SwapCanBeOptimized)
      {
        unsigned AS = GEPOp->getPointerAddressSpace();
        // Walk the indices of the GEP, accumulating them into BaseOff/VarIndices.
        gep_type_iterator GTI = gep_type_begin(GEPOp);
        for (User::const_op_iterator I = GEPOp->op_begin()+1,
             E = GEPOp->op_end(); I != E; ++I) {
          Value *Index = *I;
          // Compute the (potentially symbolic) offset in bytes for this index.
          if (StructType *STy = GTI.getStructTypeOrNull()) {
            // For a struct, add the member offset.
            GTI++;
            
            unsigned FieldNo = cast<ConstantInt>(Index)->getZExtValue();
            if (FieldNo == 0) continue;
            
          rm.gep.AddOffset(TD->getStructLayout(STy)
                                             ->getElementOffset(FieldNo));
            continue;
          }
          
          // For an array/pointer, add the element offset, explicitly scaled.
          if (ConstantInt *CIdx = dyn_cast<ConstantInt>(Index)) {
            if (CIdx->isZero()) continue;
            rm.gep.AddOffset(TD->getTypeAllocSize(GTI.getIndexedType())*CIdx
                             ->getSExtValue());
            continue;
          }
          
          uint64_t Scale = TD->getTypeAllocSize(GTI.getIndexedType());
          ExtensionKind Extension = EK_NotExtended;
          
          // If the integer type is smaller than the pointer size, it is implicitly
          // sign extended to pointer size.
          unsigned Width = Index->getType()->getIntegerBitWidth();
          if (TD->getPointerSizeInBits(AS) > Width)
            Extension = EK_SignExt;
          
          // Use GetLinearExpression to decompose the index into a C1*V+C2 form.
          APInt IndexScale(Width, 0), IndexOffset(Width, 0);
          Index = GetLinearExpression(Index, IndexScale, IndexOffset, Extension,
                                      *TD, 0);

          // The GEP index scale ("Scale") scales C1*V+C2, yielding (C1*V+C2)*Scale.
          // This gives us an aggregate computation of (C1*Scale)*V + C2*Scale.
          rm.gep.AddOffset(IndexOffset.getSExtValue()*Scale);
          Scale *= IndexScale.getSExtValue();

          // If we already had an occurrence of this index variable, merge this
          // scale into it.  For example, we want to handle:
          //   A[x][x] -> x*16 + x*4 -> x*20
          // This also ensures that 'x' only appears in the index list once.
          for (unsigned i = 0, e = rm.gep.varIndices.size(); i != e; ++i) {
            if (rm.gep.varIndices[i].V == Index &&
                rm.gep.varIndices[i].Extension == Extension) {
              Scale += rm.gep.varIndices[i].Scale; // LLVM BUG
              rm.gep.varIndices.erase(rm.gep.varIndices.begin()+i);
              break;
            }
          }
          
          // Make sure that we have a scale that makes sense for this target's
          // pointer size.
          if (unsigned ShiftBits = 64 - TD->getPointerSizeInBits(AS)) {
            Scale <<= ShiftBits;
            Scale = (int64_t)Scale >> ShiftBits;
          }
          
          if (Scale) {
            VariableGEPIndex Entry = {Index, Extension,
              static_cast<int64_t>(Scale), UINT64_MAX};
            rm.gep.varIndices.push_back(Entry);
          }
        }
      }
    }
    else if (Operator::getOpcode(V) == Instruction::BitCast)
    {
      // If they cast the pointer type, everything after the
      // cast must be assumed to be a union or overlay.
      V = cast<Operator>(V)->getOperand(0);
    }
    else if (GlobalAlias *GA = dyn_cast<GlobalAlias>(V))
    {
      V = GA->getAliasee();
    }
    else if (const Argument *A = dyn_cast<Argument>(V))
    {
      if (recursiveGetBasedAccessCall(recursions, V))
        return false;

      rm.beingProcessed = A;
      
      const Function *F = A->getParent();

      if (F->hasLocalLinkage())
      {
        unsigned int argNo = A->getArgNo();
        bool canExpand = true;
        
        // Loop through all the uses of the function to make sure they
        // are all calls and that this operand is passed.
        for (User::const_op_iterator J = F->op_begin(),
             E = F->op_end(); J != E && canExpand; J++)
        {
          const Use *U = J;
          const User *UV = U->getUser();
          const CallInst *CI = dyn_cast<CallInst>(UV);
          if (!CI)
            canExpand = false;
          else if (CI->getNumArgOperands() <= argNo)
            canExpand = false;
        }
        if (canExpand)
        {
          bool didSomething = false;

          // Loop through all the calls to the function and evaluate each
          // parameter passed to this argument.
          for (User::const_op_iterator J = F->op_begin(),
               E = F->op_end(); J != E && canExpand; J++)
          {
            const Use &U = *J;
            const User *UV = U.getUser();
            const CallInst *CI = dyn_cast<CallInst>(UV);
            assert(U == CI->getOperandUse(0) &&
                   "call function use def doesn't match");

            didSomething |= GetBasedAccessInt(CI->getArgOperand(argNo), &rm, rets);
          }

          return didSomething;
        }
      }
    }
    else if (const PHINode *P = dyn_cast<PHINode>(V))
    {
      if (recursiveGetBasedAccessCall(recursions, V))
        return false;
      
      rm.beingProcessed = P;
      bool didSomething = false;
      
      for (unsigned j = 0, e = P->getNumIncomingValues(); j < e; j++)
      {
        didSomething |= GetBasedAccessInt(P->getIncomingValue(j), &rm, rets);
      }
      return didSomething;
    }
    else if (SelectInst *SI = dyn_cast<SelectInst>(V))
    {
      if (recursiveGetBasedAccessCall(recursions, V))
        return false;
      
      rm.beingProcessed = P;
      bool didSomething = false;
      didSomething |= GetBasedAccessInt(SI->getFalseValue(), &rm, rets);
      didSomething |= GetBasedAccessInt(SI->getTrueValue(), &rm, rets);
      return didSomething;
    }
    else if (const ConstantPointerNull *CPN = dyn_cast<ConstantPointerNull>(V))
    {
      if (CPN->getType()->getAddressSpace() == 0)
        break;
    }
#if 0
    else if (const CallInst *CI = dyn_cast<CallInst>(V))
    {
      // Check for local functions?
    }
#endif
    else
    {
      // See if InstructionSimplify knows any relevant tricks.
      if (Instruction *I = dyn_cast<Instruction>(V))
        // TODO: Acquire a DominatorTree and use it.
        if (Value *Simplified = SimplifyInstruction(I, *TD, 0))
        {
          V = Simplified;
          continue;
        }
      
      break;
    }
  }

  assert(V->getType()->isPointerTy() && "Unexpected operand type!");

  ret.base = V;
  ret.gep = rm.gep;
  if (ret.swapReq == SwapCanBeOptimized)
    ret.swapReq = MustSwap;

  rets.keys.push_back(ret);
  return true;
}

bool
EndianEmulation::GetBasedAccess(Value *V, BasedAccess &rets)
{
  bool didSomething = GetBasedAccessInt(V, NULL, rets);
  return didSomething;
}

enum SwapRequirement
EndianEmulation::baseMustSwap(const Value *base)
{
  enum SwapRequirement ret = MustSwap;

  if (isa<AllocaInst>(base))
    ret = SwapCanBeOptimized;
  
  // Local globals don't always swap.
  if (const GlobalValue *gv = dyn_cast<GlobalValue>(base))
  {
    if (gv->hasLocalLinkage())
      ret = SwapCanBeOptimized;

    // Certain internal names (names with "." in them) are referenced
    // from code that is compiler generated and, more significantly,
    // the initialization of these names is internally generated and
    // the initialization is also processed from a number of places that
    // assume they know what is there.  Some of these will deftinitely
    // run after this pass.  It is not practical to find all
    // those places and teach them how to deal with bswaps.
    // Also, because these are, by definition, under the hood, there
    // is no benefit to making them appear with a different endianess.
    if (const GlobalVariable *GV = dyn_cast<GlobalVariable>(gv))
    {
      StringRef name = GV->getName();
      if (name.startswith("llvm."))
        ret = CannotSwap;
      else if (name.startswith("switch."))
        ret = CannotSwap;
   }
  }

  // Eliminate anything that's already aliased, even in the first pass.
  return ret /* || aliasedBases.find(base) != aliasedBases.end() */;
}

// Insert a swap of one input argument to an instuction.
bool
EndianEmulation::SwapArg(Instruction *IN, Value *pointerArg, int argNo)
{
  if (!SwapNeeded(IN, pointerArg))
    return false;
  Instruction *user = nullptr, *result = nullptr;
  GenerateFullBswap(TD, IN, IN->getOperand(argNo), true, user, result);
  IN->setOperand(argNo, result);
  return true;
}

// Insert a swap for the result of an instruction and replace all the uses
// with the swap result.
bool
EndianEmulation::SwapResult(Instruction *IN, Value *pointerArg)
{
  if (!SwapNeeded(IN, pointerArg))
    return false;

  Instruction *user = nullptr, *result = nullptr;
  GenerateFullBswap(TD, IN, IN, false, user, result);

  // Point all consumers at the swapped result.
  IN->replaceUsesExceptSome(result, user);
  return true;
}

static Value *
addInst (Instruction *next, Instruction *&cur, Instruction *IN,
                     bool insertBefore, Instruction *&first)
{
  next->setDebugLoc(IN->getDebugLoc());

  if (cur) {
    next->insertAfter(cur);
  }
  else
  {
    first = next;

    if (insertBefore)
      IN->insertBefore(IN);
    else
      IN->insertAfter(IN);
  }

  cur = next;

  return cur;
}

// Insert swaps the result of CmpXchg.
// Note that the result is a structure value; so, the old exchange value
// needs to be extracted, bswapped and inserted in a new result.
bool
EndianEmulation::SwapCmpXchgResult(Instruction *IN, Value *pointerArg)
{
  if (!SwapNeeded(IN, pointerArg))
    return false;

  // Now, we have to extract the value loaded, swap it, then re-insert it.
  ExtractValueInst *EVI = ExtractValueInst::Create(IN, 0);
  EVI->insertAfter(IN);
  InsertValueInst *IVI = InsertValueInst::Create(IN, EVI, 0);
  IVI->insertAfter(EVI);

  // Point all the consumers of the original instruction at the new
  // sequence, but don't wipe the references to the new instructions!
  IN->replaceUsesExceptSome(IVI, EVI, IVI);

  // Now, insert the appropriate swap for the extracted value.
  SwapResult(EVI, pointerArg);
  return true;
}

// This routine generates replacement code for atomicrmw operations which are
// not endian dependent (add, sub, min, max).  This transforms one basic
// block into three.  With the following code transformation:
//
//  <<<
//  ORES = atomicrmw(OP, R, NIV)
//  >>>
//
//  Transforms to
//
//  <<<
//  FPOV = load(R)
//  BR next
//
// next:
//  POV = PHI(FPOV, LPOV)
//  NOV = bswap(POV)
//  NV = OP(NOV, NIV)
//  PV = bswap(NV)
//  CX = cmpxchg(R, POV, NV)
//  FLAG = extractvalue(CX, 1)
//  LPOV = extractvalue(CX, 0)
//  br FLAG, done, next
//
// done:
//  RES = bswap(LPOV)
//  >>>
//
// OV = old value     IV = operand2 value
// F = first          L = looped
// P = program endian N = native endian
bool
EndianEmulation::ExpandAtomicRMW(AtomicRMWInst *IN,
                                 Value *pointerArg, unsigned opcode,
                                 CmpInst::Predicate pred)
{
  PointerType *pt = cast<PointerType>(pointerArg->getType());
  Type *t = pt->getElementType();
  BasicBlock *BB = IN->getParent();
  Module *m = BB->getParent()->getParent();
  Value *NIV = IN->getOperand(1);

  if (!SwapNeeded(IN, pointerArg))
    return false;

  BasicBlock::iterator splitPoint = BB->begin();
  for (BasicBlock::iterator e = BB->end();
       splitPoint != e; splitPoint++)
  {
    Instruction *I2 = &*splitPoint;
    if (I2 == (Instruction *)IN)
      break;
  }
  
  BasicBlock *doneBB = BB->splitBasicBlock(splitPoint);
  BasicBlock *nextBB = BasicBlock::Create(BB->getContext(), "",
                                          BB->getParent(), doneBB);
  
  // splitBasicBlock adds a branch instruction, but to the wrong place.
  BranchInst *BRI = dyn_cast<BranchInst>(BB->getTerminator());
  BRI->setSuccessor(0, nextBB);
  // Now, insert the initial load before the branch.
  LoadInst *FPOV = new LoadInst(pointerArg, "", IN->isVolatile(),
                                0, IN->getOrdering(), IN->getSynchScope(),
                                BRI);
  
  // Now, fill in the middle basic block.

  PHINode *POV = PHINode::Create(t, 2, "", nextBB);
  POV->setIncomingValue(0, FPOV);
  POV->setIncomingBlock(0, BB);
  CallInst * NOV = getBswapInstruction(m, POV);
  NOV->insertAfter(POV);
  Instruction *NV = NULL;
  if (opcode == Instruction::ICmp)
  {
    ICmpInst *CI = new ICmpInst(*nextBB, pred, NOV, NIV);
    NV = SelectInst::Create(CI, NOV, NIV, "", nextBB);
  }
  else
  {
    Instruction::BinaryOps binOp = (Instruction::BinaryOps)opcode;
    NV = BinaryOperator::Create(binOp, NOV, NIV, "", nextBB);
  }
  //  NV = OP(NOV, NIV)
  CallInst *PV = getBswapInstruction(m, NV);
  PV->insertAfter(NV);
  AtomicCmpXchgInst *CX = new AtomicCmpXchgInst(pointerArg, POV, PV,
                                                IN->getOrdering(),
                                                IN->getOrdering(),
                                                IN->getSynchScope(), nextBB);
  ExtractValueInst *FLAG = ExtractValueInst::Create(CX, 1, "", nextBB);
  ExtractValueInst *LPOV = ExtractValueInst::Create(CX, 0, "", nextBB);
  BRI = BranchInst::Create(doneBB, nextBB, FLAG, nextBB);
  POV->setIncomingValue(1, LPOV);
  POV->setIncomingBlock(1, nextBB);
  
  // Now, add the final bswap to the "done" BB.
  CallInst * RES = getBswapInstruction(m, LPOV);
  RES->insertAfter(IN);

  // Redirect the result of the AtomicRMW and delete it.
  IN->replaceAllUsesWith(RES);
  IN->eraseFromParent();
  return true;
}

void FieldOffsetMap::InsertField(const OneBasedAccess *ref, bool invalid,
                                 Value *sizeArg)
{
  uint8_t scalarSize = ref->fieldScalarSize;
  uint64_t size = scalarSize * ref->fieldElementCount;
  uint64_t offset = ref->gep.GetOffset();

  // If the size is bogus, ignore.
  if (size > AccessSizeMax)
    scalarSize = AccessSizeMultiple;
  
  if (sizeArg)
  {
    // This is for an untyped access; so, we can't optimize...
    scalarSize = AccessSizeMultiple;

    const ConstantInt *copySize = dyn_cast_or_null<ConstantInt>(sizeArg);
    if (copySize)
    {
      size = copySize->getZExtValue();
    }
    else
    {
      size = UINT64_MAX;
    }
  }
  else if (invalid)
  {
    scalarSize = AccessSizeMultiple;
  }

  if (ref->gep.varIndices.empty())
  {
    InsertIndexRange(offset, scalarSize, size, EK_ZeroExt, 0, size );
  }
  else
  {
    unsigned endIx = ref->gep.varIndices.size();
    for (unsigned ix = 0; ix < endIx; ix++)
    {
      // The scale must be a multiple of the access size to optimize.
      uint8_t thisScalarSize = (scalarSize == AccessSizeMultiple
                                || (ref->gep.varIndices[ix].Scale % scalarSize))
                            ? AccessSizeMultiple : scalarSize;

      InsertIndexRange(offset, thisScalarSize, size,
                       ref->gep.varIndices[ix].Extension,
                       ref->gep.varIndices[ix].Scale,
                       ref->gep.varIndices[ix].End );
    }
  }
}

void
FieldOffsetMap::InsertIndexRange(uint64_t offset, uint8_t accessSize,
                                 uint64_t elementSize, ExtensionKind extension,
                                 uint64_t scale, uint64_t end)
{
  // Adjust the offset for each index that can go negative.
  if (extension != EK_ZeroExt && scale >= offset)
  {
    // In a valid program, the index can go back to the beginning of
    // the base, but not before it.  Adjust the offset backwards by
    // the number of elements that will fit.
    uint64_t delta = ((scale-offset) / scale) * scale;
    offset -= delta;
    
    // The end stays in the same place.
    if (end < UINT64_MAX - delta)
      end += delta;
    else
      end = UINT64_MAX;
  }

  // If the element size is bigger than the scale, give up.
  if (elementSize > scale)
  {
  badFromOffset:
    NumRanges = FindRange(offset);
    {
      OffsetRange nr;
      nr.Offset = offset;
      nr.EndOffset = UINT64_MAX;
      nr.ElementSize = UINT64_MAX;
      nr.AccessSize = AccessSizeMultiple;
      nr.AccessScale = scale;
      
      InsertRange(nr);
    }
    return;
  }

  // Turn the end into an end offset.
  if (end < UINT64_MAX - offset)
    end += offset;
  else
    end = UINT64_MAX;

  int32_t ix = 0, nextIx = 0;
  
  // Check for overlap against all the other ranges we have.
  for ( ; ix < MaxRanges; ix = nextIx)
  {
    uint64_t shortScale = 0;
    uint64_t longScale = 0;
    uint64_t offset1 = Ranges[ix].Offset;
    uint64_t end1 = Ranges[ix].EndOffset;
    uint64_t offset2 = offset;
    uint64_t end2 = end;
    uint64_t commonOffset = 0;

    nextIx = ix+1;

    if (Ranges[ix].AccessSize == AccessSizeDeleted)
      continue;

    // Stop, because the list is sorted by offset and Ranges[ix].offset
    // can't get smaller.
    if (offset1 > end2)
      break;

    // If there is no overlap at all (even touching), move on to the next.
    if (offset2 > end1)
      continue;

    // If the scale factors are compatible, we can overlap based
    // on offsets and element sizes by figuring out the overlap within
    // the first array element.
  
    if (Ranges[ix].AccessScale < scale)
    {
      shortScale = Ranges[ix].AccessScale;
      longScale = scale;
    }
    else
    {
      shortScale = scale;
      longScale = Ranges[ix].AccessScale;
    }

    if (shortScale <= 0)
      shortScale = longScale;
    
    if (offset2 >= offset1)
    {
      commonOffset = offset1;
      if (shortScale > 0)
      {
        offset2 = (offset2 - commonOffset) % shortScale;
        offset2 += commonOffset;
        if (end2 < UINT64_MAX)
          end2 -= (offset - offset2);
      }
    }
    else
    {
      commonOffset = offset2;
      offset2 = commonOffset;
      if (shortScale > 0)
      {
        offset1 = (offset1 - commonOffset) % shortScale;
        offset1 += commonOffset;
        if (end1 < UINT64_MAX)
          end1 -= (offset - offset2);
      }
    }

    if (shortScale > 0)
    {
      // Determine if the two accesses are limited to a repeating
      // pattern.
      if (longScale % shortScale)
        goto badScales;
      
      if (offset1 + Ranges[ix].ElementSize > end1)
        goto badScales;
      
      if (offset2 + elementSize > end2)
        goto badScales;
      
      if (Ranges[ix].ElementSize > shortScale)
        goto badScales;
      
      if (elementSize > shortScale)
      {
      badScales:
        // If the scales disagree and we aren't actually overlapping, just
        // touching, we can just keep going without merging anything.
        if (offset >= Ranges[ix].EndOffset  || Ranges[ix].Offset >= end)
          continue;
        
        // Otherwise, everything from this offset onward is not
        // optimizable.
        if (Ranges[ix].Offset < offset)
          offset = Ranges[ix].Offset;
        
        goto badFromOffset;
      }
    }

    // Now, just consider overlap within the first instance of the repeat.
    uint64_t otherEnd = end1 + Ranges[ix].ElementSize;
    uint64_t elementEnd = end2+elementSize;

    // If not overlapping, we just go onto the next element.
    // Note that we do not want to merge regions that are just
    // touching, because a subsequent access using a different
    // accessSize would render then entire merge unoptimizable
    // instead of just what conflicted.  We could go through
    // and merge after the first pass, but there probably isn't
    // any point.
    if (offset2 >= otherEnd || offset1 >= elementEnd)
      continue;

    // At this point, we have overlap and we need to merge ranges.
    uint64_t commonElementEnd = (elementEnd > otherEnd) ? elementEnd : otherEnd;
    uint64_t commonElementSize = commonElementEnd - commonOffset;

    if (accessSize != AccessSizeMultiple
        && ( Ranges[ix].AccessSize != accessSize
          || ((offset1 - commonOffset) % accessSize)
          || ((offset2 - commonOffset) % accessSize)
          || (commonElementSize % accessSize) ) )
    {
      // The merged access isn't aligned with the new one;
      // so, the merge has to be marked as unoptimizable.
      accessSize = AccessSizeMultiple;
    }

    offset = commonOffset;
    elementSize = commonElementSize;
    end = (end1 >= end2) ? end1 : end2;

    if ( Ranges[ix].Offset == offset
      && Ranges[ix].EndOffset == end
      && Ranges[ix].ElementSize == elementSize
      && Ranges[ix].AccessSize == accessSize
      && Ranges[ix].AccessScale == scale)
    {
      return;
    }

    DeleteRange(ix);
    nextIx = ix;
  }
  
  OffsetRange nr;
  nr.Offset = offset;
  nr.EndOffset = end;
  nr.ElementSize = elementSize;
  nr.AccessSize = accessSize;
  nr.AccessScale = scale;
  
  InsertRange(nr);
}

bool
FieldOffsetMap::FieldMatches(const OneBasedAccess *ref, Type *elementType)
{
  uint64_t offset = ref->gep.GetOffset();
  uint8_t scalarSize = ref->fieldScalarSize;
  int64_t size = scalarSize * ref->fieldElementCount;

  if (size >= AccessSizeMax)
    return false;

  RangeMatchType matches = unknownMatch;

  if (ref->gep.varIndices.empty())
  {
    matches = IndexRangeMatches(offset, scalarSize, size, EK_ZeroExt, 0, size);
  }
  else
  {
    unsigned endIx = ref->gep.varIndices.size();
    for (unsigned ix = 0; ix < endIx; ix++)
    {
      RangeMatchType m;
      
      // The scale must be a multiple of the access size to optimize.
      uint8_t thisScalarSize = (ref->gep.varIndices[ix].Scale % scalarSize)
                                          ? AccessSizeMultiple : scalarSize;
      
      m = IndexRangeMatches(offset, thisScalarSize, size,
                            ref->gep.varIndices[ix].Extension,
                            ref->gep.varIndices[ix].Scale,
                            ref->gep.varIndices[ix].End);
      if (m > matches)
        matches = m;
    }
  }

  return (matches == singleMatch);
}

RangeMatchType
FieldOffsetMap::IndexRangeMatches(uint64_t offset, uint8_t accessSize,
                                 uint64_t elementSize, ExtensionKind extension,
                                 uint64_t scale, uint64_t end)
{
  // Adjust the offset for each index that can go negative.
  if (extension != EK_ZeroExt && scale >= offset)
  {
    // In a valid program, the index can go back to the beginning of
    // the base, but not before it.  Adjust the offset backwards by
    // the number of elements that will fit.
    uint64_t delta = ((scale-offset) / scale) * scale;
    offset -= delta;
    
    // The end stays in the same place.
    if (end < UINT64_MAX - delta)
      end += delta;
    else
      end = UINT64_MAX;
  }

  int32_t ix = FindRange(offset);
  
  while (offset > Ranges[ix].Offset)
  {
    if (ix <= 0)
      return unknownMatch;
    
    ix--;
  }
  
  if (Ranges[ix].AccessSize != accessSize)
    return multipleMatch;
  
  if (offset + accessSize > Ranges[ix].EndOffset)
    return multipleMatch;
  
  offset -= Ranges[ix].Offset;
  offset %= Ranges[ix].AccessScale;
  
  if (offset + accessSize > Ranges[ix].ElementSize)
    return multipleMatch;
  
  return (offset % accessSize) ? singleMatch : multipleMatch;
}


int32_t
FieldOffsetMap::FindRange(uint64_t offset)
{
  int32_t high = NumRanges, low = 0;

  if (high <= 0)
    return 0;

  for (;;)
  {
    int32_t mid = low + ((high - low) >> 1);

    if (Ranges[mid].Offset >= offset)
    {
      if (high == mid) // high == low, too
        break;

      high = mid;
    }
    else
    {
      if (low == mid) // high == low or high == low+1
        break;

      low = mid;
    }
  }

  return high;
}

void
FieldOffsetMap::InsertRange(OffsetRange &r)
{
  OffsetRange *oldRanges = Ranges;
  int32_t insertPoint = FindRange(r.Offset);
  
  if (NumRanges >= MaxRanges)
  {
    int32_t newMax = MaxRanges + 4;

    Ranges = new OffsetRange [newMax];
    MaxRanges = newMax;
    for (int32_t j = 0; j < insertPoint; j++)
      Ranges[j] = oldRanges[j];
  }

  for (int32_t j = NumRanges; j > insertPoint; j--)
    Ranges[j] = oldRanges[j-1];

  NumRanges++;

  if (Ranges != oldRanges && Ranges != SomeRanges)
    delete [] Ranges;
}

namespace llvm {
// This function is provided as a utility for any back ends that use
// AnyEndianness and want to provide the Endian emulation API on thier
// own.  We assume that the swapping is free in this case;
// so, we aren't worrying about whether the pointers are aliased or not.
// Note that this routine is passed both a type and an instruction --
// That makes it possible, but not currently implemned, to provide a user
// visible API for controlling where byte swapping is done.  This can either
// be done by adding a two bit field to types or using metadata.

Endianness
ComputeEndianAccessType(const Value *V, Type *t,
                        Endianness apiEndianess,
                        Endianness targetEndianess)
{
  assert((isa<Instruction>(V) || isa<Constant>(V))
         && "ComputeEndianAccessType: Bad First Argument");

  VectorType *vt = dyn_cast<VectorType>(t);
  if (vt)
    t = vt->getVectorElementType();

  switch (t->getTypeID())
  {
    case Type::FloatTyID:
      break;

    case Type::DoubleTyID:
      break;

    case Type::IntegerTyID:
      switch(cast<IntegerType>(t)->getBitWidth())
      {
        case 16:
        case 32:
        case 64:
          break;
        
        default:
          return targetEndianess;
      }
      break;

    case Type::PointerTyID:
      break;

    default:
      return targetEndianess;
  }

#if 0
  switch (t->getSpecifiedEndianess())
  {
    case Type::ProgramEndian:
      return apiEndianess;
      
    case Type::BigEndian:
      return Module::BigEndian;
      
    case Type::LittleEndian:
      return Module::LittleEndian;
      
    case Type::NativeEndian:
      return targetEndianess;
  }
#endif
  
  return targetEndianess;
}

// The bswap instruction only supports scalar integer types, but we
// need to support all first class types.  The algorithm is to first
// convert [vectors of] pointers to [vectors of] integers, if necessary.
// After that, we bitcast the result to either a scalar integer
// or a vector of i8s.
// Next, we emit a bswap for scalar integers or a shulffle for the
// vector of i8s.
// Lastly, we reverse any bitcast and/or PtrToInt.
void
GenerateFullBswap(const DataLayout *TD, Instruction *IN, Value* arg,
                  bool insertBefore, Instruction *&p_user, Instruction *&p_result)
{
  Type *T = arg->getType();
  Type *curT = T;
  Type *ptrT = nullptr, *castT = nullptr, *uncastT = nullptr;
  VectorType *VTy = nullptr;
  Module *m = IN->getParent()->getParent()->getParent();
  Instruction *cur = nullptr;
  Value *curVal = arg;
  uint64_t elementSize = TD->getTypeSizeInBits(curT);
  
  // Labels and Functions?
  
  if (curT->isPointerTy())
  {
    ptrT = curT;
    Type *newT = TD->getIntPtrType(curT);
    CastInst *PTI = CastInst::Create(Instruction::PtrToInt, curVal, newT);
    curVal = addInst(PTI, cur, IN, insertBefore, p_user);
    curT = newT;
  }
  
  if ((VTy = dyn_cast<VectorType>(curT)))
  {
    Type *eT = IntegerType::get(curT->getContext(), 8);
    castT = VectorType::get(eT, elementSize/8);
    elementSize = TD->getTypeSizeInBits(VTy->getElementType());
  }
  else
  {
    if (!curT->isIntegerTy())
    {
      // Bitcast is needed.
      castT = IntegerType::get(curT->getContext(), elementSize);
    }
  }

  if (castT)
  {
    // Bitcast is needed.
    uncastT = curT;
    CastInst *CI = CastInst::Create(Instruction::BitCast, curVal, castT);
    curVal = addInst(CI, cur, IN, insertBefore, p_user);
    curT = castT;
  }
  
  if (VTy)
  {
    ShuffleVectorInst *SI = new ShuffleVectorInst(curVal, UndefValue::get(curT),
                                  ConstantExpr::GenerateBswapShuffleMask(TD, T));
    curVal = addInst(SI, cur, IN, insertBefore, p_user);
  }
  else
  {
    CallInst *BSI = getBswapInstruction(m, curVal);
    curVal = addInst(BSI, cur, IN, insertBefore, p_user);
  }
  
  if (uncastT)
  {
    CastInst *CI = CastInst::Create(Instruction::BitCast, curVal, uncastT);
    curVal = addInst(CI, cur, IN, insertBefore, p_user);
    curT = uncastT;
  }
  
  if (ptrT)
  {
    CastInst *ITP = CastInst::Create(Instruction::IntToPtr, curVal, ptrT);
    curVal = addInst(ITP, cur, IN, insertBefore, p_user);
    curT = ptrT;
  }
  
  p_result = cur;
}

CallInst *
getBswapInstruction(Module *m, Value *op)
{
  Type *OpType = op->getType();
  Function *BswapFunc = Intrinsic::getDeclaration(
                                                  m, Intrinsic::bswap,
                                                  ArrayRef<Type*>(&OpType, 1));
  CallInst *CI = CallInst::Create(BswapFunc, op);
  return CI;
}
}

