// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#define push(R) \
	inc8 %sp, -4; st32 R, %sp

	.file           "crti.S"

	.section        ".init"
	.global         _init
	.type           _init, @function
	.p2align        1
_init:
	push(%rp)
	push(%fp)

	.section        ".fini"
	.global         _fini
	.type           _fini, @function
	.p2align        1
_fini:
	push(%rp)
	push(%fp)
