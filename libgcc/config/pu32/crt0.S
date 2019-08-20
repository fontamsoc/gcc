// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

	.text

	.global  _start
	.type    _start, @function
	.p2align 1
_start:
	# %sp, %fp and %rp are expected to have been properly set.

	# Zero section .bss .
	rli %8, __bss_start
	rli %9, __bss_end
	li8 %10, 0
0:
	cpy %11, %8
	sltu %11, %9
	rli %sr, 0f
	jz %11, %sr
	st32 %10, %8 # Write zero.
	inc8 %8, 4
	rli %sr, 0b
	j %sr
0:
	# Call global and static constructors.
	rli %sr, _init
	jl %rp, %sr

	# Setup destructors to be called from exit().
	rli %1, _fini
	rli %sr, atexit
	jl %rp, %sr

	# Call main (int argc, char *argv[], char *envp[]);
	# The stack is laid-out as follow:
	# - argc
	# - null-terminated argv pointers array.
	# - null-terminated envp pointers array.
	# - argv null-terminated strings.
	# - envp null-terminated strings.
	ld32 %1, %sp
	cpy %2, %sp
	inc8 %2, 4
	cpy %3, %1
	li8 %sr, 2
	sll %3, %sr
	add %3, %2
	inc8 %3, 4
	rli %sr, main
	jl %rp, %sr

	# Call exit().
	rli %sr, exit
	jl %rp, %sr
	# We should never return from above jl,
	# otherwise we must infinite loop.
	j %rp

	.size    _start, (. - _start)
