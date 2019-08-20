// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#define IN_TARGET_CODE 1

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "backend.h"
#include "target.h"
#include "rtl.h"
#include "tree.h"
#include "stringpool.h"
#include "attribs.h"
#include "df.h"
#include "regs.h"
#include "memmodel.h"
#include "emit-rtl.h"
#include "diagnostic-core.h"
#include "output.h"
#include "stor-layout.h"
#include "varasm.h"
#include "calls.h"
#include "expr.h"
#include "builtins.h"
#include "optabs-libfuncs.h"

/* This file should be included last.  */
#include "target-def.h"

// Enable code that make the callee prologue
// generate instructions that save registers;
// however CALL_USED_REGISTERS has been set such
// that the caller is responsible for saving
// any register that it is using, instead of
// the callee needing to save and restore
// any register that it is using.
//#define PU32_PROLOGUE_MUST_SAVE_REGISTER

#define MUST_SAVE_REGISTER(R)            \
  (((R) != FRAME_POINTER_REGNUM) &&      \
  ((R) != PU32_RETURN_POINTER_REGNUM) && \
  !fixed_regs[R] &&                      \
  df_regs_ever_live_p (R) &&             \
  !call_used_regs[R])
#define MUST_SAVE_FRAME_POINTER (df_regs_ever_live_p (FRAME_POINTER_REGNUM) || frame_pointer_needed)
// Also make %rp needed when %fp is needed,
// as it would insure that GDB can generate
// a backtrace when -fno-omit-frame-pointer
// is activated by -g .
#define MUST_SAVE_RETURN_POINTER (df_regs_ever_live_p (PU32_RETURN_POINTER_REGNUM) || frame_pointer_needed || crtl->profile)

static void pu32_operand_lossage (const char *msgid, rtx op) {
	debug_rtx (op);
	output_operand_lossage ("%s", msgid);
}

// Implement TARGET_RETURN_IN_MEMORY.
static bool pu32_return_in_memory (
	const_tree type,
	const_tree fntype ATTRIBUTE_UNUSED) {
	return ((unsigned HOST_WIDE_INT)int_size_in_bytes(type) > UNITS_PER_WORD);
}

// Implement TARGET_FUNCTION_VALUE.
static rtx pu32_function_value (
	const_tree valtype,
	const_tree fntype_or_decl ATTRIBUTE_UNUSED,
	bool outgoing ATTRIBUTE_UNUSED) {
	return gen_rtx_REG (TYPE_MODE (valtype), PU32_RETURN_VALUE_REGNUM);
}

// Implement TARGET_LIBCALL_VALUE.
static rtx pu32_libcall_value (
	machine_mode mode,
	const_rtx fun ATTRIBUTE_UNUSED) {
	return gen_rtx_REG (mode, PU32_RETURN_VALUE_REGNUM);
}

// Implement TARGET_FUNCTION_VALUE_REGNO_P.
static bool pu32_function_value_regno_p (
	const unsigned int regno) {
	return (regno == PU32_RETURN_VALUE_REGNUM);
}

// Implement TARGET_STRUCT_VALUE_RTX.
static rtx pu32_struct_value_rtx (
	tree fntype ATTRIBUTE_UNUSED,
	int incoming ATTRIBUTE_UNUSED) {
	return gen_rtx_REG (Pmode, PU32_STRUCT_VALUE_REGNUM);
}

// Implement TARGET_PRINT_OPERAND_ADDRESS.
static void pu32_print_operand_address (
	FILE *file,
	machine_mode /*mode*/,
	rtx x) {

	switch (GET_CODE (x)) {

		case REG:
			if (REGNO (x) >= FIRST_PSEUDO_REGISTER)
				internal_error ("internal error: %s: bad register: %d",
					__FUNCTION__, REGNO (x));

			fprintf (file, "%s", reg_names[REGNO (x)]);

			break;

		case PLUS:
			internal_error ("internal error: %s: unsupported", __FUNCTION__);
			break;

		default:
			output_addr_const (file, x);
			break;
	}
}

// Implement TARGET_PRINT_OPERAND.
static void pu32_print_operand (FILE *file, rtx x, int code) {

	switch (code) {

		case 0:
			// No code, print as usual.
			break;

		default:
			pu32_operand_lossage ("invalid operand modifier letter", x);
			return;
	}

	// Print an operand without a modifier letter.
	switch (GET_CODE (x)) {

		case REG:
			if (REGNO (x) >= FIRST_PSEUDO_REGISTER)
				internal_error ("internal error: %s: bad register: %d",
					__FUNCTION__, REGNO (x));

			fprintf (file, "%s", reg_names[REGNO (x)]);

			break;

		case MEM:
			output_address (GET_MODE (XEXP (x, 0)), XEXP (x, 0));
			break;

		default:
			if (CONSTANT_P (x)) {
				output_addr_const (file, x);
				break;
			}

			pu32_operand_lossage ("unexpected operand", x);
			return;
	}
}

struct GTY(()) machine_function {
	//HOST_WIDE_INT pretendargs_size;
	HOST_WIDE_INT outargs_size;
	HOST_WIDE_INT localvars_size;
	HOST_WIDE_INT savedregs_size;
	unsigned int mustsaveregs_mask;
	HOST_WIDE_INT savefp;
	HOST_WIDE_INT saverp;
	HOST_WIDE_INT outargs_size_localvars_size;
	HOST_WIDE_INT total_size;
	bool isnaked;
	bool isnoreturn;
};

// Handle an attribute requiring a FUNCTION_DECL;
// arguments as in struct attribute_spec.handler.
static tree pu32_handle_fndecl_attribute (
	tree *node, tree name,
	tree args ATTRIBUTE_UNUSED,
	int flags ATTRIBUTE_UNUSED,
	bool *no_add_attrs) {

	if (TREE_CODE (*node) != FUNCTION_DECL) {
		warning (
			OPT_Wattributes,
			"%qE attribute only applies to functions",
			name);
		*no_add_attrs = true;
	}

	return NULL_TREE;
}

// Define target-specific uses of __attribute__.
static const struct attribute_spec pu32_attribute_table[] = {
	// Syntax: {	name, min_len, max_len, decl_required, type_required,
	//		function_type_required, affects_type_identity,
	//		handler, exclude }

	// Attribute telling no prologue/epilogue.
	{ "naked", 0, 0, true, false, false, false,
	  pu32_handle_fndecl_attribute, NULL },

	// Last attribute spec must be NULL.
	{ NULL,	0,  0, false, false, false, false, NULL, NULL }
};

// Return true if function is a naked function.
static bool pu32_is_naked_function (tree func) {
	tree func_decl = func;
	if (func == NULL_TREE)
		func_decl = current_function_decl;
	return (
		lookup_attribute ("naked", DECL_ATTRIBUTES (func_decl)) !=
		NULL_TREE);
}

// Implement TARGET_ALLOCATE_STACK_SLOTS_FOR_ARGS.
static bool pu32_allocate_stack_slots_for_args () {
	// Naked functions should not allocate stack slots for arguments.
	return !pu32_is_naked_function (current_function_decl);
}

// Implement TARGET_WARN_FUNC_RETURN.
static bool pu32_warn_func_return (tree decl) {
	// Naked functions would have return sequence implemented
	// in assembly, so suppress warnings about this.
	return !pu32_is_naked_function (decl);
}

// Implement TARGET_SET_CURRENT_FUNCTION.
static void pu32_set_current_function (tree decl) {
	if (	decl == NULL_TREE ||
		current_function_decl == NULL_TREE ||
		current_function_decl == error_mark_node ||
		!cfun->machine)
		return;
	cfun->machine->isnaked = pu32_is_naked_function (decl);
	cfun->machine->isnoreturn = TREE_THIS_VOLATILE (decl);
}

const char *pu32_output_return () {
	if (cfun->machine->isnaked)
		return "";
	return "j %%rp # retlr";
}

static struct machine_function * pu32_init_machine_status (void) {
	return ggc_cleared_alloc<machine_function> ();
}

// Implement TARGET_OPTION_OVERRIDE.
static void pu32_option_override (void) {
	// Default -fdelete-null-pointer-checks to off to prevent
	// the compiler from treating accesses to address zero as traps.
	flag_delete_null_pointer_checks = 0;
	init_machine_status = pu32_init_machine_status;
}

/* Stack after function's prologue:

  SP ->+-----------------------+                         low addr
       |                       | \
       |    func arguments     |  | outargs_size
       |                       | /
       +-----------------------+
       |                       | \
       |  local variables      |  | localvars_size
       |                       | /
       +-----------------------+
       |  register save area   | \
  FP ->+-----------------------+  |
       |  previous frame ptr   |  | savedregs_size
       +-----------------------+  |
       |    return address     | /                       Callee
  AP ->+-----------------------+------------------------------------
       |                       |                         Caller
       |    func arguments     |
       |                       |
       +-----------------------+
       |                       |
       |   local variables     |
       |                       |
       +-----------------------+                         high addr
*/

static void pu32_compute_frame (void) {

	if (cfun->machine->isnaked)
		return;

	/* // pretendargs_size will always be 0 since
	// pu32_setup_incoming_varargs() is commented-out.
	// This code is kept for future reference.
	HOST_WIDE_INT pretendargs_size = crtl->args.pretend_args_size;
	cfun->machine->pretendargs_size =
		(pretendargs_size = ROUND_UP(pretendargs_size, UNITS_PER_WORD)); */

	// Note that pretendargs are part of outargs.
	HOST_WIDE_INT outargs_size = (ACCUMULATE_OUTGOING_ARGS ?
		(HOST_WIDE_INT)crtl->outgoing_args_size : 0);
	cfun->machine->outargs_size =
		(outargs_size = ROUND_UP(outargs_size, UNITS_PER_WORD));

	HOST_WIDE_INT localvars_size = get_frame_size ();
	cfun->machine->localvars_size =
		(localvars_size = ROUND_UP(localvars_size, UNITS_PER_WORD));

	unsigned int mustsaveregs_mask = 0;
	HOST_WIDE_INT savedregs_size = 0;
	for (int regno = 0; regno < FIRST_PSEUDO_REGISTER; ++regno) {
		if (MUST_SAVE_REGISTER(regno)) {
			#if !defined(PU32_PROLOGUE_MUST_SAVE_REGISTER)
			internal_error ("internal error: %s: caller's unsaved register: %s",
					__FUNCTION__, reg_names[regno]);
			#else
			// Note that MUST_SAVE_REGISTER() ignore
			// FRAME_POINTER_REGNUM and PU32_RETURN_POINTER_REGNUM
			// as they are checked by MUST_SAVE_FRAME_POINTER
			// and MUST_SAVE_RETURN_POINTER to set savefp
			// and saverp respectively.
			mustsaveregs_mask |= (1 << regno);
			savedregs_size += UNITS_PER_WORD;
			#endif
		}
	}
	cfun->machine->mustsaveregs_mask = mustsaveregs_mask;
	HOST_WIDE_INT savefp = !!MUST_SAVE_FRAME_POINTER;
	HOST_WIDE_INT saverp = !!MUST_SAVE_RETURN_POINTER && !cfun->machine->isnoreturn;
	savedregs_size = savedregs_size + ((savefp+saverp)*UNITS_PER_WORD);
	cfun->machine->savedregs_size = savedregs_size;
	cfun->machine->savefp = savefp;
	cfun->machine->saverp = saverp;

	cfun->machine->outargs_size_localvars_size =
		outargs_size + localvars_size;

	cfun->machine->total_size =
		outargs_size + localvars_size + savedregs_size;
}

int pu32_initial_elimination_offset (int from, int to) {

	pu32_compute_frame ();

	HOST_WIDE_INT offset = 0;

	if (from == ARG_POINTER_REGNUM && to == STACK_POINTER_REGNUM)
		offset = cfun->machine->total_size;
	else if (from == ARG_POINTER_REGNUM && to == FRAME_POINTER_REGNUM)
		offset = ((cfun->machine->savefp + cfun->machine->saverp) * UNITS_PER_WORD);
	else if (from == FRAME_POINTER_REGNUM && to == STACK_POINTER_REGNUM)
		offset = (cfun->machine->total_size -
			((cfun->machine->savefp + cfun->machine->saverp) * UNITS_PER_WORD));
	else
		gcc_unreachable ();

	return offset;
}

void pu32_expand_prologue (void) {

	pu32_compute_frame ();

	if (flag_stack_usage_info)
		current_function_static_stack_size =
			cfun->machine->total_size;

	if (cfun->machine->saverp) {
		rtx insn = emit_insn (
			gen_movsi_push (
				gen_rtx_REG (
					Pmode, PU32_RETURN_POINTER_REGNUM)));
		RTX_FRAME_RELATED_P (insn) = 1;
	}

	if (cfun->machine->savefp) {
		rtx insn = emit_insn (
			gen_movsi_push (
				gen_rtx_REG (
					Pmode, FRAME_POINTER_REGNUM)));
		RTX_FRAME_RELATED_P (insn) = 1;
		if (frame_pointer_needed) {
			insn = emit_insn (
				gen_movsi (
					gen_rtx_REG (
						Pmode, FRAME_POINTER_REGNUM),
					gen_rtx_REG (
						Pmode, STACK_POINTER_REGNUM)));
			RTX_FRAME_RELATED_P (insn) = 1;
		}
	}

	unsigned int mustsaveregs_mask = cfun->machine->mustsaveregs_mask;
	if (cfun->machine->savedregs_size) {
		for (int regno = (FIRST_PSEUDO_REGISTER-1); regno--;) {
			if (mustsaveregs_mask & (1 << regno)) {
				rtx insn = emit_insn (
					gen_movsi_push (
						gen_rtx_REG (
							Pmode, regno)));
				RTX_FRAME_RELATED_P (insn) = 1;
			}
		}
	}

	// Note that pretendargs are part of outargs.
	HOST_WIDE_INT outargs_size_localvars_size =
		cfun->machine->outargs_size_localvars_size;
	if (outargs_size_localvars_size) {
		rtx insn = emit_insn (
			gen_subsi3 (
				gen_rtx_REG (
					Pmode, STACK_POINTER_REGNUM),
				gen_rtx_REG (
					Pmode, STACK_POINTER_REGNUM),
				GEN_INT (outargs_size_localvars_size)));
		RTX_FRAME_RELATED_P (insn) = 1;
	}

	emit_insn (gen_blockage ());
}

void pu32_expand_epilogue (void) {

	HOST_WIDE_INT outargs_size_localvars_size =
		cfun->machine->outargs_size_localvars_size;
	if (outargs_size_localvars_size) {
		emit_insn (
			gen_addsi3 (
				gen_rtx_REG (
					Pmode, STACK_POINTER_REGNUM),
				gen_rtx_REG (
					Pmode, STACK_POINTER_REGNUM),
				GEN_INT (outargs_size_localvars_size)));
	}

	unsigned int mustsaveregs_mask = cfun->machine->mustsaveregs_mask;
	if (cfun->machine->savedregs_size) {
		for (int regno = 0; regno < FIRST_PSEUDO_REGISTER; ++regno) {
			if (mustsaveregs_mask & (1 << regno)) {
				emit_insn (
					gen_movsi_pop (
						gen_rtx_REG (Pmode, regno)));
			}
		}
	}

	if (cfun->machine->savefp) {
		emit_insn (
			gen_movsi_pop (
				gen_rtx_REG (
					Pmode, FRAME_POINTER_REGNUM)));
	}

	if (cfun->machine->saverp) {
		emit_insn (
			gen_movsi_pop (
				gen_rtx_REG (
					Pmode, PU32_RETURN_POINTER_REGNUM)));
	}

	if (!cfun->machine->isnaked)
		emit_jump_insn (gen_retlr ());

	emit_insn (gen_blockage ());
}

// Implement TARGET_ASM_FUNCTION_PROLOGUE.
// The content produced from this function
// will be placed before prologue body.
static void pu32_asm_function_prologue (FILE *file) {
	// All stack frame information is supposed to be
	// already computed when expanding prologue.
	// The result is in cfun->machine.
	// DO NOT call pu32_compute_stack_frame() here
	// because it may corrupt the essential information.

	fprintf (file, "\t# BEGIN PROLOGUE\n");
	//fprintf (file, "\t# pretendargs_size:  %d\n", cfun->machine->pretendargs_size);
	fprintf (file, "\t# outargs_size:      %ld\n", cfun->machine->outargs_size);
	fprintf (file, "\t# localvars_size:    %ld\n", cfun->machine->localvars_size);
	fprintf (file, "\t# savedregs_size:    %ld\n", cfun->machine->savedregs_size);
	fprintf (file, "\t# mustsaveregs_mask:");
	for (unsigned int regno = 0, mustsaveregs_mask = cfun->machine->mustsaveregs_mask;
		regno < FIRST_PSEUDO_REGISTER; ++regno) {
		if (mustsaveregs_mask & (1 << regno)) {
			fprintf (file, " %%%s", reg_names[regno]);
		}
	}
	fputc ('\n', file);
	fprintf (file, "\t# savefp:            %ld\n", cfun->machine->savefp);
	fprintf (file, "\t# saverp:            %ld\n", cfun->machine->saverp);
}

// Implement TARGET_ASM_FUNCTION_END_PROLOGUE.
// After rtl prologue has been expanded,
// this function is used.
static void pu32_asm_function_end_prologue (FILE *file) {
	fprintf (file, "\t# END PROLOGUE\n");
}

// Implement TARGET_ASM_FUNCTION_BEGIN_EPILOGUE.
// Before rtl epilogue has been expanded,
// this function is used.
static void pu32_asm_function_begin_epilogue (FILE *file) {
	fprintf (file, "\t# BEGIN EPILOGUE\n");
}

// Implement TARGET_ASM_FUNCTION_EPILOGUE.
// The content produced from this function
// will be placed after epilogue body.
static void pu32_asm_function_epilogue (FILE *file) {
	fprintf (file, "\t# END EPILOGUE\n");
}

/* // Commented out but kept for future reference.
// In fact, pu32_function_arg() is implemented such that
// the caller pass varargs through the stack, instead of
// through registers; this way only those arguments used
// by the caller get written in the stack.
// Implement TARGET_SETUP_INCOMING_VARARGS.
static void pu32_setup_incoming_varargs (
	cumulative_args_t cum_v,
	const function_arg_info &arg ATTRIBUTE_UNUSED,
	int *pretend_size,
	int no_rtl) {

	if (no_rtl) return;

	CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);

	for (int r = *cum, e = (PU32_FIRST_ARG_REGNUM + PU32_NUM_ARG_REGS);
		r < e; ++r) {

		rtx reg = gen_rtx_REG (SImode, r);

		rtx slot = gen_rtx_PLUS (Pmode,
			gen_rtx_REG (SImode, ARG_POINTER_REGNUM),
			GEN_INT (FIRST_PARM_OFFSET() + (UNITS_PER_WORD*(r-PU32_FIRST_ARG_REGNUM))));

		emit_move_insn (gen_rtx_MEM (SImode, slot), reg);
	}

	*pretend_size = (PU32_NUM_ARG_REGS * UNITS_PER_WORD);
}*/

// Implement TARGET_FUNCTION_ARG.
static rtx pu32_function_arg (
	cumulative_args_t cum_v,
	const function_arg_info &arg) {
	CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);
	return ((*cum < (PU32_FIRST_ARG_REGNUM + PU32_NUM_ARG_REGS)) && arg.named) ?
		gen_rtx_REG (arg.mode, *cum) : NULL_RTX;
}

// Implement TARGET_FUNCTION_ARG_ADVANCE.
static void pu32_function_arg_advance (
	cumulative_args_t cum_v,
	const function_arg_info &arg ATTRIBUTE_UNUSED) {
	CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);
	*cum = (*cum < (PU32_FIRST_ARG_REGNUM + PU32_NUM_ARG_REGS) ? *cum + 1 : *cum);
}

// Implement TARGET_PASS_BY_REFERENCE.
static bool pu32_pass_by_reference (
	cumulative_args_t cum ATTRIBUTE_UNUSED,
	const function_arg_info &arg) {
	machine_mode mode = arg.mode;
	const_tree type = arg.type;
	return (((mode != BLKmode && mode != VOIDmode) ?
			GET_MODE_SIZE(mode) :
			(unsigned HOST_WIDE_INT)int_size_in_bytes(type)) >
		UNITS_PER_WORD);
}

// Implement TARGET_ARG_PARTIAL_BYTES.
static int pu32_arg_partial_bytes (
	cumulative_args_t cum_v ATTRIBUTE_UNUSED,
	const function_arg_info &arg ATTRIBUTE_UNUSED) {
	return 0;
}

// Implement TARGET_MUST_PASS_IN_STACK.
static bool pu32_must_pass_in_stack (
	const function_arg_info &arg ATTRIBUTE_UNUSED) {
	return false;
}

static bool pu32_reg_ok_for_base_p (const_rtx reg, bool strict_p) {

	int regno = REGNO (reg);

	if (strict_p)
		return HARD_REGNO_OK_FOR_BASE_P (regno);
	else
		return (regno >= FIRST_PSEUDO_REGISTER) ||
			HARD_REGNO_OK_FOR_BASE_P (regno);
}

// Implement TARGET_LEGITIMATE_ADDRESS_P.
static bool pu32_legitimate_address_p (
	machine_mode mode ATTRIBUTE_UNUSED,
	rtx x,
	bool strict_p) {

	if (REG_P (x) && pu32_reg_ok_for_base_p (x, strict_p))
		return true;

	if (GET_CODE (x) == SYMBOL_REF    ||
		GET_CODE (x) == LABEL_REF ||
		GET_CODE (x) == CONST)
		return true;

	return false;
}

#if 0
// Implement TARGET_ASM_TRAMPOLINE_TEMPLATE.
static void pu32_asm_trampoline_template (FILE *f) {
	fprintf (f, "\tnop; li32 %s, 0\n", // 8 bytes; imm word-aligned at offset 4.
		reg_names[STATIC_CHAIN_REGNUM]);
	char *r = (char *)reg_names[PU32_SCRATCH_REGNUM];
	fprintf (f, "\tnop; rli32 %s, 0\n", r); // 8 bytes; imm word-aligned at offset 12.
	fprintf (f, "\tj %s\n", r); // 2 bytes.
}

// Implement TARGET_TRAMPOLINE_INIT.
static void pu32_trampoline_init (
	rtx m_tramp,
	tree fndecl,
	rtx chain_value) {

	emit_block_move (m_tramp,
		assemble_trampoline_template (),
		GEN_INT (TRAMPOLINE_SIZE),
		BLOCK_OP_NORMAL);

	rtx mem = adjust_address (m_tramp, SImode, 4);
	emit_move_insn (mem, chain_value);
	mem = adjust_address (m_tramp, SImode, 12);
	emit_move_insn (mem, XEXP (DECL_RTL (fndecl), 0));
}
#endif

static GTY(()) rtx pu32_tga = NULL;
rtx gen_pu32_tga (void) {
	if (!pu32_tga)
		pu32_tga = init_one_libfunc ("__tls_get_addr");
	return pu32_tga;
}

#undef  TARGET_PROMOTE_PROTOTYPES
#define TARGET_PROMOTE_PROTOTYPES hook_bool_const_tree_true

#undef  TARGET_RETURN_IN_MEMORY
#define TARGET_RETURN_IN_MEMORY pu32_return_in_memory
#undef  TARGET_MUST_PASS_IN_STACK
#define TARGET_MUST_PASS_IN_STACK pu32_must_pass_in_stack
#undef  TARGET_PASS_BY_REFERENCE
#define TARGET_PASS_BY_REFERENCE pu32_pass_by_reference
#undef  TARGET_ARG_PARTIAL_BYTES
#define TARGET_ARG_PARTIAL_BYTES pu32_arg_partial_bytes
#undef  TARGET_FUNCTION_ARG
#define TARGET_FUNCTION_ARG pu32_function_arg
#undef  TARGET_FUNCTION_ARG_ADVANCE
#define TARGET_FUNCTION_ARG_ADVANCE pu32_function_arg_advance
#undef  TARGET_STRICT_ARGUMENT_NAMING
#define TARGET_STRICT_ARGUMENT_NAMING hook_bool_CUMULATIVE_ARGS_true

#undef TARGET_LRA_P
#define TARGET_LRA_P hook_bool_void_false

#undef  TARGET_LEGITIMATE_ADDRESS_P
#define TARGET_LEGITIMATE_ADDRESS_P pu32_legitimate_address_p

#undef TARGET_ASM_FUNCTION_PROLOGUE
#define TARGET_ASM_FUNCTION_PROLOGUE pu32_asm_function_prologue
#undef TARGET_ASM_FUNCTION_END_PROLOGUE
#define TARGET_ASM_FUNCTION_END_PROLOGUE pu32_asm_function_end_prologue
#undef  TARGET_ASM_FUNCTION_BEGIN_EPILOGUE
#define TARGET_ASM_FUNCTION_BEGIN_EPILOGUE pu32_asm_function_begin_epilogue
#undef TARGET_ASM_FUNCTION_EPILOGUE
#define TARGET_ASM_FUNCTION_EPILOGUE pu32_asm_function_epilogue

//#undef  TARGET_SETUP_INCOMING_VARARGS
//#define TARGET_SETUP_INCOMING_VARARGS pu32_setup_incoming_varargs

#undef TARGET_FUNCTION_VALUE
#define TARGET_FUNCTION_VALUE pu32_function_value
#undef TARGET_LIBCALL_VALUE
#define TARGET_LIBCALL_VALUE pu32_libcall_value
#undef TARGET_FUNCTION_VALUE_REGNO_P
#define TARGET_FUNCTION_VALUE_REGNO_P pu32_function_value_regno_p
#undef TARGET_STRUCT_VALUE_RTX
#define TARGET_STRUCT_VALUE_RTX pu32_struct_value_rtx

#undef TARGET_CUSTOM_FUNCTION_DESCRIPTORS
#define TARGET_CUSTOM_FUNCTION_DESCRIPTORS 1
//#undef TARGET_ASM_TRAMPOLINE_TEMPLATE
//#define TARGET_ASM_TRAMPOLINE_TEMPLATE pu32_asm_trampoline_template
//#undef TARGET_TRAMPOLINE_INIT
//#define TARGET_TRAMPOLINE_INIT pu32_trampoline_init

#undef TARGET_OPTION_OVERRIDE
#define TARGET_OPTION_OVERRIDE pu32_option_override

#undef  TARGET_PRINT_OPERAND
#define TARGET_PRINT_OPERAND pu32_print_operand
#undef  TARGET_PRINT_OPERAND_ADDRESS
#define TARGET_PRINT_OPERAND_ADDRESS pu32_print_operand_address

#undef  TARGET_CONSTANT_ALIGNMENT
#define TARGET_CONSTANT_ALIGNMENT constant_alignment_word_strings

#undef  TARGET_ATTRIBUTE_TABLE
#define TARGET_ATTRIBUTE_TABLE pu32_attribute_table
#undef  TARGET_ALLOCATE_STACK_SLOTS_FOR_ARGS
#define TARGET_ALLOCATE_STACK_SLOTS_FOR_ARGS pu32_allocate_stack_slots_for_args
#undef  TARGET_WARN_FUNC_RETURN
#define TARGET_WARN_FUNC_RETURN pu32_warn_func_return
#undef  TARGET_SET_CURRENT_FUNCTION
#define TARGET_SET_CURRENT_FUNCTION pu32_set_current_function

#undef  TARGET_HAVE_TLS
#define TARGET_HAVE_TLS true

struct gcc_target targetm = TARGET_INITIALIZER;

#include "gt-pu32.h"
