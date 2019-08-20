// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#define pop(R) \
	ld32 R, %sp; inc8 %sp, 4

	.file           "crtn.S"

	.section        ".init"
	pop(%fp)
	pop(%rp)
	j %rp # retlr

	.section        ".fini"
	pop(%fp)
	pop(%rp)
	j %rp # retlr
