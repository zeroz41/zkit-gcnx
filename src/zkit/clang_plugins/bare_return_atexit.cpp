// zkit clang plugin "bare-return-atexit" (build.clang_plugins): GlobalOpt removes a __cxa_atexit registration
// only when the destructor's own entry block is a bare `ret`.
//
// LLVM up to 8 (OptimizeEmptyGlobalCXXDtors -> cxxDtorIsEmpty) also counts a destructor as empty when it only
// calls empty functions, such as empty base-class destructors, and drops the registration; LLVM 9 and later do not
// recurse. A game built by a toolchain with the later rule keeps those registrations (and the guarded static's
// code around them) where a stock older clang removes them. This pass applies the non-recursive rule itself, then
// hides __cxa_atexit from GlobalOpt and restores the name before code generation, so nothing else changes.
// Built by zkit against the project clang's own LLVM headers (legacy pass manager, loaded with -Xclang -load).
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {

const char kName[] = "__cxa_atexit";
const char kHidden[] = "__zkit_hidden_cxa_atexit";

// LLVM 9's cxxDtorIsEmpty: the entry block is debug intrinsics then `ret`.
bool dtorIsBareReturn(const Function &Fn) {
  if (Fn.isDeclaration())
    return false;
  for (const Instruction &I : Fn.getEntryBlock()) {
    if (isa<DbgInfoIntrinsic>(I))
      continue;
    return isa<ReturnInst>(I);
  }
  return false;
}

bool removeEmptyDtorRegistrations(Function &AtExit) {
  bool Changed = false;
  for (auto UI = AtExit.user_begin(), UE = AtExit.user_end(); UI != UE;) {
    CallInst *CI = dyn_cast<CallInst>(*UI++);
    if (!CI || CI->getCalledFunction() != &AtExit)
      continue;
    Function *Dtor =
        dyn_cast<Function>(CI->getArgOperand(0)->stripPointerCasts());
    if (!Dtor || !dtorIsBareReturn(*Dtor))
      continue;
    CI->replaceAllUsesWith(Constant::getNullValue(CI->getType()));
    CI->eraseFromParent();
    Changed = true;
  }
  return Changed;
}

struct RenameAtExit : public ModulePass {
  static char ID;
  bool Hide;
  explicit RenameAtExit(bool Hide) : ModulePass(ID), Hide(Hide) {}
  bool runOnModule(Module &M) override {
    Function *F = M.getFunction(Hide ? kName : kHidden);
    if (!F)
      return false;
    if (!Hide) {
      if (Function *Real = M.getFunction(kName)) {
        F->replaceAllUsesWith(ConstantExpr::getBitCast(Real, F->getType()));
        F->eraseFromParent();
        return true;
      }
    }
    if (Hide)
      removeEmptyDtorRegistrations(*F);
    F->setName(Hide ? kHidden : kName);
    return true;
  }
};
char RenameAtExit::ID = 0;

void addHide(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new RenameAtExit(true));
}
void addRestore(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new RenameAtExit(false));
}

RegisterStandardPasses Hide(PassManagerBuilder::EP_ModuleOptimizerEarly, addHide);
RegisterStandardPasses Restore(PassManagerBuilder::EP_OptimizerLast, addRestore);

} // namespace
