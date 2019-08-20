// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#ifndef GCC_PU32_H
#define GCC_PU32_H

#undef  STARTFILE_SPEC
#define STARTFILE_SPEC "%{!mno-crt0:%{!shared:%{!symbolic:%:if-exists-else(crt1%O%s crt0%O%s)}}} crti.o%s %{fno-exceptions:crtbegin_no_eh.o%s; :crtbegin.o%s}"

#undef  ENDFILE_SPEC
#define ENDFILE_SPEC "%{fno-exceptions:crtend_no_eh.o%s; :crtend.o%s} crtn.o%s"

#undef CPP_SPEC
#define CPP_SPEC "%{posix:-D_POSIX_SOURCE} %{pthread:-D_REENTRANT}"

#undef LIB_SPEC
#define LIB_SPEC "%{!shared:%{!symbolic:-lc}} %{pthread:-lpthread}"

#undef  LINK_SPEC
#define LINK_SPEC "%{h*} %{v:-V} %{static:-Bstatic} %{shared:-shared} %{symbolic:-Bsymbolic} %{rdynamic:-export-dynamic}"

#undef  ASM_SPEC
#define ASM_SPEC "%{ffixed-*:-mfixed-%*} -mrelax"

#define ASM_COMMENT_START "#"
#define ASM_APP_ON ""
#define ASM_APP_OFF ""

#define FILE_ASM_OP "\t.file\n"
#define TEXT_SECTION_ASM_OP "\t.text"
#define DATA_SECTION_ASM_OP "\t.data"
#define ASM_OUTPUT_ALIGN(STREAM,POWER)       \
  fprintf (STREAM, "\t.p2align\t%d\n", POWER);
#define GLOBAL_ASM_OP "\t.global\t"

#define TARGET_CPU_CPP_BUILTINS() { \
  builtin_define ("__PU32__");      \
}

#define TARGET_OS_CPP_BUILTINS()      \
  do {                                \
    builtin_define ("__gnu_linux__"); \
    builtin_define_std ("linux");     \
    builtin_define_std ("unix");      \
  } while (0)

#define INT_TYPE_SIZE 32
#define SHORT_TYPE_SIZE 16
#define LONG_TYPE_SIZE 32
#define LONG_LONG_TYPE_SIZE 64

#define FLOAT_TYPE_SIZE 32
#define DOUBLE_TYPE_SIZE 64
#define LONG_DOUBLE_TYPE_SIZE 64

#define DEFAULT_SIGNED_CHAR 1

#undef  SIZE_TYPE
#define SIZE_TYPE "unsigned int"

#undef  PTRDIFF_TYPE
#define PTRDIFF_TYPE "int"

#undef  WCHAR_TYPE
#define WCHAR_TYPE "int"

#define UNITS_PER_WORD 4

#define BITS_PER_WORD 32

#undef  WCHAR_TYPE_SIZE
#define WCHAR_TYPE_SIZE BITS_PER_WORD

#define FIRST_PSEUDO_REGISTER 17

#define PU32_FIRST_ARG_REGNUM 1
// Use all registers that are not reserved, except
// for %8 and %9 otherwise GCC can complain: unable
// to find a register to spill in class ‘GENERAL_REGS’.
// Reserved regiters start from %10.
// It is ideal to have 7 registers because Linux takes
// at most 6 syscall arguments, which means GLIBC syscall()
// function implemented in sysdeps/unix/sysv/linux/pu32/syscall.S
// needs 7 arguments, which corresponds nicely.
#define PU32_NUM_ARG_REGS 7

// Must match what the assembler and disassembler use,
// as well as match the names used in REGISTER_NAMES.
#define STACK_POINTER_REGNUM 0
#define PU32_RETURN_VALUE_REGNUM PU32_FIRST_ARG_REGNUM
#define PU32_TASK_POINTER_REGNUM 10 /* Used by Linux-Kernel as %tp through -Wa,mfixed-%10 */
#define PU32_STRUCT_VALUE_REGNUM 11
#define STATIC_CHAIN_REGNUM 12
#define PU32_SCRATCH_REGNUM 13
#define FRAME_POINTER_REGNUM 14
#define PU32_RETURN_POINTER_REGNUM 15
#define ARG_POINTER_REGNUM 16

#define ELIMINABLE_REGS {                         \
  { ARG_POINTER_REGNUM,   STACK_POINTER_REGNUM }, \
  { ARG_POINTER_REGNUM,   FRAME_POINTER_REGNUM }, \
  { FRAME_POINTER_REGNUM, STACK_POINTER_REGNUM }, \
}

#define INITIAL_ELIMINATION_OFFSET(FROM, TO, OFFSET)      \
  (OFFSET) = pu32_initial_elimination_offset ((FROM), (TO))

#define STACK_POINTER_OFFSET 0

#define FIRST_PARM_OFFSET(F) 0

enum reg_class {
  NO_REGS,
  GENERAL_REGS,
  ALL_REGS,
  LIM_REG_CLASSES
};

#define N_REG_CLASSES LIM_REG_CLASSES

#define REG_CLASS_CONTENTS {           \
  { 0x00000000 }, /* Empty */          \
  { 0x0001FFFF }, /* %0 to %15, %ap */ \
  { 0x0001FFFF }  /* All registers */  \
}

#define REG_CLASS_NAMES { \
  "NO_REGS",              \
  "GENERAL_REGS",         \
  "ALL_REGS"              \
}

#define REGISTER_NAMES {      \
  "%sp",  "%1",  "%2",  "%3", \
  "%4",  "%5",  "%6",  "%7",  \
  "%8",  "%9",  "%10", "%11", \
  "%12", "%sr", "%fp", "%rp", \
  "%ap"                       \
}

#define FIXED_REGISTERS { \
  1, 0, 0, 0,             \
  0, 0, 0, 0,             \
  0, 0, 0, 0,             \
  0, 1, 1, 1,             \
  1                       \
}

// All fields set 1; making the caller responsible
// for saving registers that it is using, instead of
// the callee needing to save and restore registers
// that it is using.
#define CALL_USED_REGISTERS { \
  1, 1, 1, 1,                 \
  1, 1, 1, 1,                 \
  1, 1, 1, 1,                 \
  1, 1, 1, 1,                 \
  1                           \
}

#define REGNO_REG_CLASS(R) (((R) <= 16) ? GENERAL_REGS : NO_REGS)

#define ACCUMULATE_OUTGOING_ARGS 1

#define CUMULATIVE_ARGS unsigned int

#define INIT_CUMULATIVE_ARGS(CUM,FNTYPE,LIBNAME,FNDECL,N_NAMED_ARGS) \
  (CUM = PU32_FIRST_ARG_REGNUM)

#define FRAME_GROWS_DOWNWARD 1
#define STACK_GROWS_DOWNWARD 1

#define OUTGOING_REG_PARM_STACK_SPACE(FNTYPE) 1

#define BITS_BIG_ENDIAN 0
#define BYTES_BIG_ENDIAN 0
#define WORDS_BIG_ENDIAN 0

#define FUNCTION_BOUNDARY 16

#define SLOW_BYTE_ACCESS 1

#define STACK_BOUNDARY BITS_PER_WORD

#define PARM_BOUNDARY BITS_PER_WORD

#define EMPTY_FIELD_BOUNDARY BITS_PER_WORD

#define BIGGEST_ALIGNMENT BITS_PER_WORD

#define FASTEST_ALIGNMENT BITS_PER_WORD

#define PCC_BITFIELD_TYPE_MATTERS 1

#define MAX_FIXED_MODE_SIZE BITS_PER_WORD

#define DATA_ALIGNMENT(TYPE, ALIGN)                        \
  (TREE_CODE (TYPE) == ARRAY_TYPE &&                       \
  TYPE_MODE (TREE_TYPE (TYPE)) == QImode &&                \
  (ALIGN) < FASTEST_ALIGNMENT ? FASTEST_ALIGNMENT : (ALIGN))

#define STRICT_ALIGNMENT 1

#define FUNCTION_PROFILER(FILE,LABELNO) (abort(), 0)

#define TRAMPOLINE_SIZE (8 + 8 + 2)
#define TRAMPOLINE_ALIGNMENT BITS_PER_WORD

#define Pmode SImode

#define FUNCTION_MODE SImode

#define FUNCTION_ARG_REGNO_P(R)                    \
  (((R) >= PU32_FIRST_ARG_REGNUM) &&               \
  ((R) < (PU32_FIRST_ARG_REGNUM+PU32_NUM_ARG_REGS)))

#define BASE_REG_CLASS GENERAL_REGS
#define INDEX_REG_CLASS GENERAL_REGS

#define HARD_REGNO_OK_FOR_BASE_P(R)  \
  (REGNO_REG_CLASS(R) == GENERAL_REGS)

#ifdef REG_OK_STRICT
#define REGNO_OK_FOR_BASE_P(R) \
  HARD_REGNO_OK_FOR_BASE_P(R)
#else
#define REGNO_OK_FOR_BASE_P(R)     \
  ((R) >= FIRST_PSEUDO_REGISTER || \
  HARD_REGNO_OK_FOR_BASE_P(R))
#endif

#define REGNO_OK_FOR_INDEX_P(R) REGNO_OK_FOR_BASE_P(R)

#define MOVE_MAX UNITS_PER_WORD

#define LOAD_EXTEND_OP(M) ZERO_EXTEND

#define MAX_REGS_PER_ADDRESS 1

#define CASE_VECTOR_MODE SImode

#define HAS_LONG_UNCOND_BRANCH true

#define DEFAULT_PCC_STRUCT_RETURN 0

#define INCOMING_RETURN_ADDR_RTX                \
  gen_rtx_REG (Pmode, PU32_RETURN_POINTER_REGNUM)
#define EH_RETURN_DATA_REGNO(N)                 \
  (((N) < PU32_NUM_ARG_REGS) ?                  \
    (PU32_FIRST_ARG_REGNUM+(N)) : INVALID_REGNUM)
#define EH_RETURN_HANDLER_RTX                   \
  gen_rtx_REG (Pmode, PU32_RETURN_POINTER_REGNUM)

#endif /* GCC_PU32_H */
