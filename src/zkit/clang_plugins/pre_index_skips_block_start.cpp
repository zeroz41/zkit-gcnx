// zkit clang plugin "pre-index-skips-block-start" (build.clang_plugins): the AArch64 load/store optimizer does not
// fold an `add/sub xN, xN, #imm` that is the first instruction of a block (other than the function's entry block)
// into a following `ldr/str [xN]`.
//
// Before LLVM commit 173b14db7c9c (February 2016, "fix bug in pre-inc check iterator"), the backward search of
// AArch64LoadStoreOptimizer for a pre-index update (findMatchingUpdateInsnBackward) stopped before a block's first
// instruction, so `sub x0, x0, #16; ldr x8, [x0]` at the start of a block stayed two instructions. LLVM 3.9 and
// later examine that instruction too and emit `ldr x8, [x0, #-16]!`. A game built by a toolchain from before the fix
// keeps those pairs where a stock clang 3.9 or later folds them; mid-block updates fold on both. Such a toolchain
// was seen still folding them in entry blocks (as if something invisible came first there), so those are left alone.
//
// This pass runs right before the load/store optimizer and puts a DBG_VALUE of xN right after such a block-first
// update. The backward search counts a debug value's register as a use and stops there; the pairing, store-to-load
// and post-index searches skip debug values, the schedulers carry them along, and they emit no code. It is added
// through the codegen pipeline's one insertion point for a named pass (-print-machineinstrs=<pass>, whose printer
// pass is replaced by this one), so that option can't print in the same compile.
// Built by zkit against the project clang's own LLVM headers (legacy pass manager, loaded with -Xclang -load).
#include <cstdint> // before LLVM 4.0's STLExtras.h, which uses intptr_t without it
#include "llvm/Config/llvm-config.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/InitializePasses.h"
#include "llvm/PassInfo.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/CommandLine.h"
#if LLVM_VERSION_MAJOR >= 6
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#else
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetSubtargetInfo.h"
#endif

using namespace llvm;

namespace {

// The pass the load/store optimizer follows (AArch64PassConfig::addPreSched2), registered when the target is.
const char kAfter[] = "aarch64-expand-pseudo";

const Function &function(const MachineFunction &MF) {
#if LLVM_VERSION_MAJOR >= 6
  return MF.getFunction();
#else
  return *MF.getFunction();
#endif
}

// `add/sub xN, xN, #imm` (the update instructions the pre-index merge takes).
bool isSelfUpdate(const MachineInstr &MI, const TargetInstrInfo &TII) {
  StringRef Name = TII.getName(MI.getOpcode());
  if (Name != "ADDXri" && Name != "SUBXri")
    return false;
  return MI.getNumOperands() >= 3 && MI.getOperand(0).isReg() && MI.getOperand(1).isReg() &&
         MI.getOperand(0).getReg() == MI.getOperand(1).getReg() && MI.getOperand(2).isImm();
}

struct MarkBlockStartUpdates : public MachineFunctionPass {
  static char ID;
  MarkBlockStartUpdates() : MachineFunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    const TargetInstrInfo &TII = *MF.getSubtarget().getInstrInfo();
    const MDNode *Var = nullptr, *Expr = nullptr;
    DebugLoc Loc;
    bool Changed = false;
    for (MachineBasicBlock &MBB : MF) {
      if (&MBB == &MF.front() || MBB.empty() || !isSelfUpdate(*MBB.begin(), TII))
        continue;
      if (!Var)
        makeVariable(function(MF), Var, Expr, Loc);
      unsigned Reg = MBB.begin()->getOperand(0).getReg();
#if LLVM_VERSION_MAJOR >= 6
      BuildMI(MBB, std::next(MBB.begin()), Loc, TII.get(TargetOpcode::DBG_VALUE), false, Reg, Var, Expr);
#else
      BuildMI(MBB, std::next(MBB.begin()), Loc, TII.get(TargetOpcode::DBG_VALUE), false, Reg, 0, Var, Expr);
#endif
      Changed = true;
    }
    return Changed;
  }

  // A nameless variable for the markers: in the function's own subprogram when it has debug info (an extra
  // location-only variable there), else in an empty file scope that nothing emits.
  static void makeVariable(const Function &F, const MDNode *&Var, const MDNode *&Expr, DebugLoc &Loc) {
    LLVMContext &Ctx = F.getContext();
    Metadata *Scope = F.getSubprogram();
    if (!Scope)
      Scope = DIFile::get(Ctx, "", "");
#if LLVM_VERSION_MAJOR >= 4
    Var = DILocalVariable::get(Ctx, Scope, nullptr, nullptr, 0, nullptr, 0, DINode::FlagZero, 0);
#else
    Var = DILocalVariable::get(Ctx, Scope, nullptr, nullptr, 0, nullptr, 0, 0);
#endif
    Expr = DIExpression::get(Ctx, None);
    Loc = DebugLoc(DILocation::get(Ctx, 0, 0, Scope));
  }
};
char MarkBlockStartUpdates::ID = 0;

Pass *createMarkBlockStartUpdates() { return new MarkBlockStartUpdates(); }

// At load: when the clang has the AArch64 backend, insert the pass after kAfter in place of the printer.
struct Install {
  Install() {
    PassRegistry &Registry = *PassRegistry::getPassRegistry();
    if (!Registry.getPassInfo(StringRef(kAfter)))
      return;
    initializeMachineFunctionPrinterPassPass(Registry);
    const PassInfo *Printer = Registry.getPassInfo(StringRef("machineinstr-printer"));
    StringMap<cl::Option *> &Options = cl::getRegisteredOptions();
    auto Option = Options.find("print-machineinstrs");
    if (!Printer || Option == Options.end())
      return;
    const_cast<PassInfo *>(Printer)->setNormalCtor(createMarkBlockStartUpdates);
    Option->second->addOccurrence(0, "print-machineinstrs", kAfter);
  }
} Installed;

} // namespace
