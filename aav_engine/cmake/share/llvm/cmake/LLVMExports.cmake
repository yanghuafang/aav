# LLVM CMake target exports.  Do not include directly.
add_library(LLVMLTO STATIC IMPORTED)
set_property(TARGET LLVMLTO PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMLTO.a")
add_library(LLVMObjCARCOpts STATIC IMPORTED)
set_property(TARGET LLVMObjCARCOpts PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMObjCARCOpts.a")
add_library(LLVMLinker STATIC IMPORTED)
set_property(TARGET LLVMLinker PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMLinker.a")
add_library(LLVMipo STATIC IMPORTED)
set_property(TARGET LLVMipo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMipo.a")
add_library(LLVMVectorize STATIC IMPORTED)
set_property(TARGET LLVMVectorize PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMVectorize.a")
add_library(LLVMBitWriter STATIC IMPORTED)
set_property(TARGET LLVMBitWriter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMBitWriter.a")
add_library(LLVMIRReader STATIC IMPORTED)
set_property(TARGET LLVMIRReader PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMIRReader.a")
add_library(LLVMAsmParser STATIC IMPORTED)
set_property(TARGET LLVMAsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAsmParser.a")
add_library(LLVMR600CodeGen STATIC IMPORTED)
set_property(TARGET LLVMR600CodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMR600CodeGen.a")
add_library(LLVMR600Desc STATIC IMPORTED)
set_property(TARGET LLVMR600Desc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMR600Desc.a")
add_library(LLVMR600Info STATIC IMPORTED)
set_property(TARGET LLVMR600Info PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMR600Info.a")
add_library(LLVMR600AsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMR600AsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMR600AsmPrinter.a")
add_library(LLVMSystemZDisassembler STATIC IMPORTED)
set_property(TARGET LLVMSystemZDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSystemZDisassembler.a")
add_library(LLVMSystemZCodeGen STATIC IMPORTED)
set_property(TARGET LLVMSystemZCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSystemZCodeGen.a")
add_library(LLVMSystemZAsmParser STATIC IMPORTED)
set_property(TARGET LLVMSystemZAsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSystemZAsmParser.a")
add_library(LLVMSystemZDesc STATIC IMPORTED)
set_property(TARGET LLVMSystemZDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSystemZDesc.a")
add_library(LLVMSystemZInfo STATIC IMPORTED)
set_property(TARGET LLVMSystemZInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSystemZInfo.a")
add_library(LLVMSystemZAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMSystemZAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSystemZAsmPrinter.a")
add_library(LLVMHexagonCodeGen STATIC IMPORTED)
set_property(TARGET LLVMHexagonCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMHexagonCodeGen.a")
add_library(LLVMHexagonAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMHexagonAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMHexagonAsmPrinter.a")
add_library(LLVMHexagonDesc STATIC IMPORTED)
set_property(TARGET LLVMHexagonDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMHexagonDesc.a")
add_library(LLVMHexagonInfo STATIC IMPORTED)
set_property(TARGET LLVMHexagonInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMHexagonInfo.a")
add_library(LLVMNVPTXCodeGen STATIC IMPORTED)
set_property(TARGET LLVMNVPTXCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMNVPTXCodeGen.a")
add_library(LLVMNVPTXDesc STATIC IMPORTED)
set_property(TARGET LLVMNVPTXDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMNVPTXDesc.a")
add_library(LLVMNVPTXInfo STATIC IMPORTED)
set_property(TARGET LLVMNVPTXInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMNVPTXInfo.a")
add_library(LLVMNVPTXAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMNVPTXAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMNVPTXAsmPrinter.a")
add_library(LLVMCppBackendCodeGen STATIC IMPORTED)
set_property(TARGET LLVMCppBackendCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMCppBackendCodeGen.a")
add_library(LLVMCppBackendInfo STATIC IMPORTED)
set_property(TARGET LLVMCppBackendInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMCppBackendInfo.a")
add_library(LLVMMSP430CodeGen STATIC IMPORTED)
set_property(TARGET LLVMMSP430CodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMSP430CodeGen.a")
add_library(LLVMMSP430Desc STATIC IMPORTED)
set_property(TARGET LLVMMSP430Desc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMSP430Desc.a")
add_library(LLVMMSP430Info STATIC IMPORTED)
set_property(TARGET LLVMMSP430Info PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMSP430Info.a")
add_library(LLVMMSP430AsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMMSP430AsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMSP430AsmPrinter.a")
add_library(LLVMXCoreDisassembler STATIC IMPORTED)
set_property(TARGET LLVMXCoreDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMXCoreDisassembler.a")
add_library(LLVMXCoreCodeGen STATIC IMPORTED)
set_property(TARGET LLVMXCoreCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMXCoreCodeGen.a")
add_library(LLVMXCoreDesc STATIC IMPORTED)
set_property(TARGET LLVMXCoreDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMXCoreDesc.a")
add_library(LLVMXCoreInfo STATIC IMPORTED)
set_property(TARGET LLVMXCoreInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMXCoreInfo.a")
add_library(LLVMXCoreAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMXCoreAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMXCoreAsmPrinter.a")
add_library(LLVMMipsDisassembler STATIC IMPORTED)
set_property(TARGET LLVMMipsDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMipsDisassembler.a")
add_library(LLVMMipsCodeGen STATIC IMPORTED)
set_property(TARGET LLVMMipsCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMipsCodeGen.a")
add_library(LLVMMipsAsmParser STATIC IMPORTED)
set_property(TARGET LLVMMipsAsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMipsAsmParser.a")
add_library(LLVMMipsDesc STATIC IMPORTED)
set_property(TARGET LLVMMipsDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMipsDesc.a")
add_library(LLVMMipsInfo STATIC IMPORTED)
set_property(TARGET LLVMMipsInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMipsInfo.a")
add_library(LLVMMipsAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMMipsAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMipsAsmPrinter.a")
add_library(LLVMAArch64Disassembler STATIC IMPORTED)
set_property(TARGET LLVMAArch64Disassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64Disassembler.a")
add_library(LLVMAArch64CodeGen STATIC IMPORTED)
set_property(TARGET LLVMAArch64CodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64CodeGen.a")
add_library(LLVMAArch64AsmParser STATIC IMPORTED)
set_property(TARGET LLVMAArch64AsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64AsmParser.a")
add_library(LLVMAArch64Desc STATIC IMPORTED)
set_property(TARGET LLVMAArch64Desc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64Desc.a")
add_library(LLVMAArch64Info STATIC IMPORTED)
set_property(TARGET LLVMAArch64Info PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64Info.a")
add_library(LLVMAArch64AsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMAArch64AsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64AsmPrinter.a")
add_library(LLVMAArch64Utils STATIC IMPORTED)
set_property(TARGET LLVMAArch64Utils PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAArch64Utils.a")
add_library(LLVMARMDisassembler STATIC IMPORTED)
set_property(TARGET LLVMARMDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMARMDisassembler.a")
add_library(LLVMARMCodeGen STATIC IMPORTED)
set_property(TARGET LLVMARMCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMARMCodeGen.a")
add_library(LLVMARMAsmParser STATIC IMPORTED)
set_property(TARGET LLVMARMAsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMARMAsmParser.a")
add_library(LLVMARMDesc STATIC IMPORTED)
set_property(TARGET LLVMARMDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMARMDesc.a")
add_library(LLVMARMInfo STATIC IMPORTED)
set_property(TARGET LLVMARMInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMARMInfo.a")
add_library(LLVMARMAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMARMAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMARMAsmPrinter.a")
add_library(LLVMPowerPCDisassembler STATIC IMPORTED)
set_property(TARGET LLVMPowerPCDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMPowerPCDisassembler.a")
add_library(LLVMPowerPCCodeGen STATIC IMPORTED)
set_property(TARGET LLVMPowerPCCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMPowerPCCodeGen.a")
add_library(LLVMPowerPCAsmParser STATIC IMPORTED)
set_property(TARGET LLVMPowerPCAsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMPowerPCAsmParser.a")
add_library(LLVMPowerPCDesc STATIC IMPORTED)
set_property(TARGET LLVMPowerPCDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMPowerPCDesc.a")
add_library(LLVMPowerPCInfo STATIC IMPORTED)
set_property(TARGET LLVMPowerPCInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMPowerPCInfo.a")
add_library(LLVMPowerPCAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMPowerPCAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMPowerPCAsmPrinter.a")
add_library(LLVMSparcDisassembler STATIC IMPORTED)
set_property(TARGET LLVMSparcDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSparcDisassembler.a")
add_library(LLVMSparcCodeGen STATIC IMPORTED)
set_property(TARGET LLVMSparcCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSparcCodeGen.a")
add_library(LLVMSparcAsmParser STATIC IMPORTED)
set_property(TARGET LLVMSparcAsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSparcAsmParser.a")
add_library(LLVMSparcDesc STATIC IMPORTED)
set_property(TARGET LLVMSparcDesc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSparcDesc.a")
add_library(LLVMSparcInfo STATIC IMPORTED)
set_property(TARGET LLVMSparcInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSparcInfo.a")
add_library(LLVMSparcAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMSparcAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSparcAsmPrinter.a")
add_library(LLVMTableGen STATIC IMPORTED)
set_property(TARGET LLVMTableGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMTableGen.a")
add_library(LLVMDebugInfo STATIC IMPORTED)
set_property(TARGET LLVMDebugInfo PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMDebugInfo.a")
add_library(LLVMOption STATIC IMPORTED)
set_property(TARGET LLVMOption PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMOption.a")
add_library(LLVMX86Disassembler STATIC IMPORTED)
set_property(TARGET LLVMX86Disassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86Disassembler.a")
add_library(LLVMX86AsmParser STATIC IMPORTED)
set_property(TARGET LLVMX86AsmParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86AsmParser.a")
add_library(LLVMX86CodeGen STATIC IMPORTED)
set_property(TARGET LLVMX86CodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86CodeGen.a")
add_library(LLVMSelectionDAG STATIC IMPORTED)
set_property(TARGET LLVMSelectionDAG PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSelectionDAG.a")
add_library(LLVMAsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMAsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAsmPrinter.a")
add_library(LLVMX86Desc STATIC IMPORTED)
set_property(TARGET LLVMX86Desc PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86Desc.a")
add_library(LLVMX86Info STATIC IMPORTED)
set_property(TARGET LLVMX86Info PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86Info.a")
add_library(LLVMX86AsmPrinter STATIC IMPORTED)
set_property(TARGET LLVMX86AsmPrinter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86AsmPrinter.a")
add_library(LLVMX86Utils STATIC IMPORTED)
set_property(TARGET LLVMX86Utils PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMX86Utils.a")
add_library(LLVMJIT STATIC IMPORTED)
set_property(TARGET LLVMJIT PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMJIT.a")
add_library(LLVMLineEditor STATIC IMPORTED)
set_property(TARGET LLVMLineEditor PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMLineEditor.a")
add_library(LLVMMCAnalysis STATIC IMPORTED)
set_property(TARGET LLVMMCAnalysis PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMCAnalysis.a")
add_library(LLVMMCDisassembler STATIC IMPORTED)
set_property(TARGET LLVMMCDisassembler PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMCDisassembler.a")
add_library(LLVMInstrumentation STATIC IMPORTED)
set_property(TARGET LLVMInstrumentation PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMInstrumentation.a")
add_library(LLVMInterpreter STATIC IMPORTED)
set_property(TARGET LLVMInterpreter PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMInterpreter.a")
add_library(LLVMCodeGen STATIC IMPORTED)
set_property(TARGET LLVMCodeGen PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMCodeGen.a")
add_library(LLVMScalarOpts STATIC IMPORTED)
set_property(TARGET LLVMScalarOpts PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMScalarOpts.a")
add_library(LLVMInstCombine STATIC IMPORTED)
set_property(TARGET LLVMInstCombine PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMInstCombine.a")
add_library(LLVMTransformUtils STATIC IMPORTED)
set_property(TARGET LLVMTransformUtils PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMTransformUtils.a")
add_library(LLVMipa STATIC IMPORTED)
set_property(TARGET LLVMipa PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMipa.a")
add_library(LLVMAnalysis STATIC IMPORTED)
set_property(TARGET LLVMAnalysis PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMAnalysis.a")
add_library(LLVMProfileData STATIC IMPORTED)
set_property(TARGET LLVMProfileData PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMProfileData.a")
add_library(LLVMMCJIT STATIC IMPORTED)
set_property(TARGET LLVMMCJIT PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMCJIT.a")
add_library(LLVMTarget STATIC IMPORTED)
set_property(TARGET LLVMTarget PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMTarget.a")
add_library(LLVMRuntimeDyld STATIC IMPORTED)
set_property(TARGET LLVMRuntimeDyld PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMRuntimeDyld.a")
add_library(LLVMObject STATIC IMPORTED)
set_property(TARGET LLVMObject PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMObject.a")
add_library(LLVMMCParser STATIC IMPORTED)
set_property(TARGET LLVMMCParser PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMCParser.a")
add_library(LLVMBitReader STATIC IMPORTED)
set_property(TARGET LLVMBitReader PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMBitReader.a")
add_library(LLVMExecutionEngine STATIC IMPORTED)
set_property(TARGET LLVMExecutionEngine PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMExecutionEngine.a")
add_library(LLVMMC STATIC IMPORTED)
set_property(TARGET LLVMMC PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMMC.a")
add_library(LLVMCore STATIC IMPORTED)
set_property(TARGET LLVMCore PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMCore.a")
add_library(LLVMSupport STATIC IMPORTED)
set_property(TARGET LLVMSupport PROPERTY IMPORTED_LOCATION "/usr/local/llvm/lib/libLLVMSupport.a")
# Explicit library dependency information.
#
# The following property assignments tell CMake about link
# dependencies of libraries imported from LLVM.
set_property(TARGET LLVMSupport PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES )
set_property(TARGET LLVMAArch64Utils PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMMC PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMAArch64AsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAArch64Utils LLVMMC LLVMSupport)
set_property(TARGET LLVMAArch64Info PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMAArch64Desc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAArch64AsmPrinter LLVMAArch64Info LLVMMC LLVMSupport)
set_property(TARGET LLVMMCParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMAArch64AsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAArch64Desc LLVMAArch64Info LLVMAArch64Utils LLVMMC LLVMMCParser LLVMSupport)
set_property(TARGET LLVMCore PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMTarget PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMMC LLVMSupport)
set_property(TARGET LLVMAnalysis PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMSupport LLVMTarget)
set_property(TARGET LLVMipa PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMSupport)
set_property(TARGET LLVMTransformUtils PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMSupport LLVMTarget LLVMipa)
set_property(TARGET LLVMInstCombine PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMScalarOpts PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMInstCombine LLVMSupport LLVMTarget LLVMTransformUtils LLVMipa)
set_property(TARGET LLVMCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMMC LLVMScalarOpts LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCodeGen LLVMCore LLVMMC LLVMMCParser LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMSelectionDAG PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCodeGen LLVMCore LLVMMC LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMAArch64CodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAArch64AsmPrinter LLVMAArch64Desc LLVMAArch64Info LLVMAArch64Utils LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMScalarOpts LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMAArch64Disassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAArch64Info LLVMAArch64Utils LLVMMC LLVMSupport)
set_property(TARGET LLVMARMAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMARMInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMARMDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMARMAsmPrinter LLVMARMInfo LLVMMC LLVMSupport)
set_property(TARGET LLVMARMAsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMARMDesc LLVMARMInfo LLVMMC LLVMMCParser LLVMSupport)
set_property(TARGET LLVMARMCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMARMAsmPrinter LLVMARMDesc LLVMARMInfo LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMScalarOpts LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMARMDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMARMDesc LLVMARMInfo LLVMMC LLVMSupport)
set_property(TARGET LLVMAsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMSupport)
set_property(TARGET LLVMBitReader PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMSupport)
set_property(TARGET LLVMBitWriter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMSupport)
set_property(TARGET LLVMCppBackendInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMCppBackendCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMCppBackendInfo LLVMSupport LLVMTarget)
set_property(TARGET LLVMObject PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMBitReader LLVMCore LLVMMC LLVMMCParser LLVMSupport)
set_property(TARGET LLVMDebugInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMObject LLVMSupport)
set_property(TARGET LLVMExecutionEngine PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMMC LLVMSupport)
set_property(TARGET LLVMJIT PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCodeGen LLVMCore LLVMExecutionEngine LLVMSupport)
set_property(TARGET LLVMHexagonInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMHexagonDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMHexagonInfo LLVMMC)
set_property(TARGET LLVMHexagonAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMHexagonDesc LLVMMC LLVMSupport)
set_property(TARGET LLVMHexagonCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMHexagonAsmPrinter LLVMHexagonDesc LLVMHexagonInfo LLVMMC LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMVectorize PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMipo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMInstCombine LLVMScalarOpts LLVMSupport LLVMTarget LLVMTransformUtils LLVMVectorize LLVMipa)
set_property(TARGET LLVMIRReader PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAsmParser LLVMBitReader LLVMCore LLVMSupport)
set_property(TARGET LLVMInstrumentation PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMInterpreter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCodeGen LLVMCore LLVMExecutionEngine LLVMSupport)
set_property(TARGET LLVMLinker PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMSupport LLVMTransformUtils)
set_property(TARGET LLVMObjCARCOpts PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMCore LLVMSupport LLVMTransformUtils)
set_property(TARGET LLVMLTO PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMBitReader LLVMBitWriter LLVMCore LLVMInstCombine LLVMLinker LLVMMC LLVMObjCARCOpts LLVMObject LLVMScalarOpts LLVMSupport LLVMTarget LLVMTransformUtils LLVMipa LLVMipo)
set_property(TARGET LLVMLineEditor PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMMCAnalysis PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMObject LLVMSupport)
set_property(TARGET LLVMMCDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMRuntimeDyld PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMObject LLVMSupport)
set_property(TARGET LLVMMCJIT PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMCore LLVMExecutionEngine LLVMObject LLVMRuntimeDyld LLVMSupport LLVMTarget)
set_property(TARGET LLVMMSP430AsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMMSP430Info PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMMSP430Desc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMSP430AsmPrinter LLVMMSP430Info)
set_property(TARGET LLVMMSP430CodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMMSP430AsmPrinter LLVMMSP430Desc LLVMMSP430Info LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMMipsAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMMipsInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMMipsDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMipsAsmPrinter LLVMMipsInfo LLVMSupport)
set_property(TARGET LLVMMipsAsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMCParser LLVMMipsDesc LLVMMipsInfo LLVMSupport)
set_property(TARGET LLVMMipsCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMMipsAsmPrinter LLVMMipsDesc LLVMMipsInfo LLVMScalarOpts LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMMipsDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMipsInfo LLVMSupport)
set_property(TARGET LLVMNVPTXAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMNVPTXInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMNVPTXDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMNVPTXAsmPrinter LLVMNVPTXInfo LLVMSupport)
set_property(TARGET LLVMNVPTXCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMNVPTXAsmPrinter LLVMNVPTXDesc LLVMNVPTXInfo LLVMScalarOpts LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMX86Utils PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMX86AsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport LLVMX86Utils)
set_property(TARGET LLVMX86Info PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMX86Desc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMObject LLVMSupport LLVMX86AsmPrinter LLVMX86Info)
set_property(TARGET LLVMX86CodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMSelectionDAG LLVMSupport LLVMTarget LLVMX86AsmPrinter LLVMX86Desc LLVMX86Info LLVMX86Utils)
set_property(TARGET LLVMOption PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMPowerPCAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMPowerPCInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMPowerPCDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMPowerPCAsmPrinter LLVMPowerPCInfo LLVMSupport)
set_property(TARGET LLVMPowerPCAsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMCParser LLVMPowerPCDesc LLVMPowerPCInfo LLVMSupport)
set_property(TARGET LLVMPowerPCCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMPowerPCAsmPrinter LLVMPowerPCDesc LLVMPowerPCInfo LLVMSelectionDAG LLVMSupport LLVMTarget LLVMTransformUtils)
set_property(TARGET LLVMPowerPCDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMPowerPCInfo LLVMSupport)
set_property(TARGET LLVMProfileData PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMR600AsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMR600Info PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMR600Desc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMR600AsmPrinter LLVMR600Info LLVMSupport)
set_property(TARGET LLVMR600CodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMR600AsmPrinter LLVMR600Desc LLVMR600Info LLVMScalarOpts LLVMSelectionDAG LLVMSupport LLVMTarget)
set_property(TARGET LLVMSparcAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMSparcInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMSparcDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSparcAsmPrinter LLVMSparcInfo LLVMSupport)
set_property(TARGET LLVMSparcAsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMCParser LLVMSparcDesc LLVMSparcInfo LLVMSupport)
set_property(TARGET LLVMSparcCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMSelectionDAG LLVMSparcAsmPrinter LLVMSparcDesc LLVMSparcInfo LLVMSupport LLVMTarget)
set_property(TARGET LLVMSparcDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSparcInfo LLVMSupport)
set_property(TARGET LLVMSystemZAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMSystemZInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMSystemZDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport LLVMSystemZAsmPrinter LLVMSystemZInfo)
set_property(TARGET LLVMSystemZAsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMCParser LLVMSupport LLVMSystemZDesc LLVMSystemZInfo)
set_property(TARGET LLVMSystemZCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMScalarOpts LLVMSelectionDAG LLVMSupport LLVMSystemZAsmPrinter LLVMSystemZDesc LLVMSystemZInfo LLVMTarget)
set_property(TARGET LLVMSystemZDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport LLVMSystemZDesc LLVMSystemZInfo)
set_property(TARGET LLVMTableGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMX86AsmParser PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMMCParser LLVMSupport LLVMX86Desc LLVMX86Info)
set_property(TARGET LLVMX86Disassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport LLVMX86Info)
set_property(TARGET LLVMXCoreAsmPrinter PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport)
set_property(TARGET LLVMXCoreInfo PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMSupport)
set_property(TARGET LLVMXCoreDesc PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport LLVMXCoreAsmPrinter LLVMXCoreInfo)
set_property(TARGET LLVMXCoreCodeGen PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMAnalysis LLVMAsmPrinter LLVMCodeGen LLVMCore LLVMMC LLVMSelectionDAG LLVMSupport LLVMTarget LLVMTransformUtils LLVMXCoreAsmPrinter LLVMXCoreDesc LLVMXCoreInfo)
set_property(TARGET LLVMXCoreDisassembler PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES LLVMMC LLVMSupport LLVMXCoreInfo)
set_property(TARGET LLVMSupport APPEND PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES z pthread tinfo dl m )
