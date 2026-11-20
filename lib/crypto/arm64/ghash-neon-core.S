/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Accelerated GHASH implementation with ARMv8 ASIMD instructions.
 *
 * Copyright (C) 2014 - 2018 Linaro Ltd. <ard.biesheuvel@linaro.org>
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

	SHASH		.req	v0
	SHASH2		.req	v1
	T1		.req	v2
	T2		.req	v3
	NEXT		.req	v4
	XM		.req	v5
	XL		.req	v6
	XH		.req	v7
	IN1		.req	v7

	k00_16		.req	v8
	k32_48		.req	v9

	t3		.req	v10
	t4		.req	v11
	t5		.req	v12
	t6		.req	v13
	t7		.req	v14
	t8		.req	v15
	t9		.req	v16

	perm1		.req	v17
	perm2		.req	v18
	perm3		.req	v19

	sh1		.req	v20
	sh2		.req	v21
	sh3		.req	v22
	sh4		.req	v23

	ss1		.req	v24
	ss2		.req	v25
	ss3		.req	v26
	ss4		.req	v27

	pack1		.req	v28
	pack2		.req	v29
	pack3		.req	v30
	pack4		.req	v31

	.text
	.arch		armv8-a

	.macro		__pmull_p8, rq, ad, bd
	ext		t3.8b, \ad\().8b, \ad\().8b, #1		// A1
	ext		t5.8b, \ad\().8b, \ad\().8b, #2		// A2
	ext		t7.8b, \ad\().8b, \ad\().8b, #3		// A3

	__pmull_p8_\bd	\rq, \ad
	.endm

	.macro		__pmull2_p8, rq, ad, bd
	tbl		t3.16b, {\ad\().16b}, perm1.16b		// A1
	tbl		t5.16b, {\ad\().16b}, perm2.16b		// A2
	tbl		t7.16b, {\ad\().16b}, perm3.16b		// A3

	__pmull2_p8_\bd	\rq, \ad
	.endm

	.macro		__pmull_p8_SHASH, rq, ad
	__pmull_p8_tail	\rq, \ad\().8b, SHASH.8b, 8b,, sh1, sh2, sh3, sh4
	.endm

	.macro		__pmull_p8_SHASH2, rq, ad
	__pmull_p8_tail	\rq, \ad\().8b, SHASH2.8b, 8b,, ss1, ss2, ss3, ss4
	.endm

	.macro		__pmull2_p8_SHASH, rq, ad
	__pmull_p8_tail	\rq, \ad\().16b, SHASH.16b, 16b, 2, sh1, sh2, sh3, sh4
	.endm

	.macro		__pmull_p8_tail, rq, ad, bd, nb, t, b1, b2, b3, b4
	/* Start with an unrotated operand, then fill XOR latency with multiplies. */
	pmull\t		t4.8h, \ad, \b1\().\nb			// E = A*B1
	pmull\t		t3.8h, t3.\nb, \bd			// F = A1*B
	pmull\t		t6.8h, \ad, \b2\().\nb			// G = A*B2
	pmull\t		t5.8h, t5.\nb, \bd			// H = A2*B
	pmull\t		t8.8h, \ad, \b3\().\nb			// I = A*B3
	pmull\t		t7.8h, t7.\nb, \bd			// J = A3*B
	eor		t3.16b, t3.16b, t4.16b			// L = E + F
	eor		t5.16b, t5.16b, t6.16b			// M = G + H
	pmull\t		t9.8h, \ad, \b4\().\nb			// K = A*B4
	eor		t7.16b, t7.16b, t8.16b			// N = I + J
	/* rq may alias ad: this must remain the last multiply reading ad. */
	pmull\t		\rq\().8h, \ad, \bd			// D = A*B

	__pmull_p8_combine \rq
	.endm

	.macro		__pmull_p8_combine, rq
	uzp1		t4.2d, t3.2d, t5.2d
	uzp2		t3.2d, t3.2d, t5.2d
	uzp1		t6.2d, t7.2d, t9.2d
	uzp2		t7.2d, t7.2d, t9.2d

	// t3 = (L) (P0 + P1) << 8
	// t5 = (M) (P2 + P3) << 16
	eor		t4.16b, t4.16b, t3.16b
	and		t3.16b, t3.16b, k32_48.16b

	// t7 = (N) (P4 + P5) << 24
	// t9 = (K) (P6 + P7) << 32
	eor		t6.16b, t6.16b, t7.16b
	and		t7.16b, t7.16b, k00_16.16b

	eor		t4.16b, t4.16b, t3.16b
	eor		t6.16b, t6.16b, t7.16b

	/*
	 * Fuse each 64-bit ZIP and byte rotation into one fixed permutation.
	 * Read both members of each pair before overwriting a table register.
	 */
	tbl		t5.16b, {t3.16b, t4.16b}, pack2.16b
	tbl		t3.16b, {t3.16b, t4.16b}, pack1.16b
	tbl		t9.16b, {t6.16b, t7.16b}, pack4.16b
	tbl		t7.16b, {t6.16b, t7.16b}, pack3.16b

	eor		t3.16b, t3.16b, t5.16b
	eor		t7.16b, t7.16b, t9.16b
	eor		\rq\().16b, \rq\().16b, t3.16b
	eor		\rq\().16b, \rq\().16b, t7.16b
	.endm

	.macro		__pmull_pre_p8, keys=1
	adr_l		x5, .Lghash_neon_pack
	ld1		{pack1.16b-pack4.16b}, [x5]

	.if		\keys
	ext		SHASH2.16b, SHASH.16b, SHASH.16b, #8
	eor		SHASH2.16b, SHASH2.16b, SHASH.16b
	.endif

	// k00_16 := 0x0000000000000000_000000000000ffff
	// k32_48 := 0x00000000ffffffff_0000ffffffffffff
	movi		k32_48.2d, #0xffffffff
	mov		k32_48.h[2], k32_48.h[0]
	ushr		k00_16.2d, k32_48.2d, #32

	// prepare the permutation vectors
	mov_q		x5, 0x080f0e0d0c0b0a09
	movi		T1.8b, #8
	dup		perm1.2d, x5
	eor		perm1.16b, perm1.16b, T1.16b
	ushr		perm2.2d, perm1.2d, #8
	ushr		perm3.2d, perm1.2d, #16
	ushr		T1.2d, perm1.2d, #24
	sli		perm2.2d, perm1.2d, #56
	sli		perm3.2d, perm1.2d, #48
	sli		T1.2d, perm1.2d, #40

	// precompute loop invariants
	.if		\keys
	tbl		sh1.16b, {SHASH.16b}, perm1.16b
	tbl		sh2.16b, {SHASH.16b}, perm2.16b
	tbl		sh3.16b, {SHASH.16b}, perm3.16b
	tbl		sh4.16b, {SHASH.16b}, T1.16b
	ext		ss1.8b, SHASH2.8b, SHASH2.8b, #1
	ext		ss2.8b, SHASH2.8b, SHASH2.8b, #2
	ext		ss3.8b, SHASH2.8b, SHASH2.8b, #3
	ext		ss4.8b, SHASH2.8b, SHASH2.8b, #4
	.endif
	.endm

	.macro		__pmull_reduce_p8_sched
	eor		XM.16b, XM.16b, T1.16b
	zip1		XL.2d, XL.2d, XM.2d
	zip2		XH.2d, XM.2d, XH.2d

	/* Independent shifts feed a balanced XOR tree instead of a chain. */
	shl		T1.2d, XL.2d, #57
	shl		T2.2d, XL.2d, #62
	shl		t8.2d, XL.2d, #63
	ext		t9.16b, XL.16b, XH.16b, #8
	eor		T2.16b, T2.16b, T1.16b
	eor		t8.16b, t8.16b, t9.16b
	eor		T2.16b, T2.16b, t8.16b
	zip1		XL.2d, XL.2d, T2.2d
	zip2		XH.2d, T2.2d, XH.2d

	/* (L ^ (L >> 1)) >> 1 == (L >> 1) ^ (L >> 2), per lane. */
	ushr		T1.2d, XL.2d, #1
	ushr		T2.2d, XL.2d, #2
	ushr		t8.2d, XL.2d, #7
	eor		XH.16b, XH.16b, XL.16b
	eor		T1.16b, T1.16b, T2.16b
	eor		t8.16b, t8.16b, XH.16b
	eor		XL.16b, T1.16b, t8.16b
	.endm


	/*
	 * Single-key helper, also used by POLYVAL multiplication with zero input.
	 * x0: nonzero block count, x1: little-endian POLYVAL accumulator,
	 * x2: GHASH input bytes, x3: little-endian POLYVAL key.
	 */
SYM_FUNC_START(pmull_ghash_update_p8)
	ld1		{SHASH.16b}, [x3]
	ld1		{XL.16b}, [x1]
	ld1		{NEXT.2d}, [x2], #16
	__pmull_pre_p8

1:
	ext		T2.16b, XL.16b, XL.16b, #8
	rev64		T1.16b, NEXT.16b
	sub		x0, x0, #1
	ext		IN1.16b, T1.16b, T1.16b, #8
	eor		T1.16b, T1.16b, T2.16b
	eor		XL.16b, XL.16b, IN1.16b

	__pmull2_p8	XH, XL, SHASH
	eor		T1.16b, T1.16b, XL.16b
	/* Never load beyond the full blocks supplied by the caller. */
	cbz		x0, 2f
	ld1		{NEXT.2d}, [x2], #16
2:
	__pmull_p8	XL, XL, SHASH
	__pmull_p8	XM, T1, SHASH2

	eor		T2.16b, XL.16b, XH.16b
	ext		T1.16b, XL.16b, XH.16b, #8
	eor		XM.16b, XM.16b, T2.16b
	__pmull_reduce_p8_sched
	cbnz		x0, 1b

	st1		{XL.16b}, [x1]
	ret
SYM_FUNC_END(pmull_ghash_update_p8)

	/*
	 * XOR two independent 64x64 polynomial products. Each lane holds one
	 * operand pair. The five key rotations are already in SHASH/sh1..sh4;
	 * optionally overlap loading the next table with these multiplies.
	 * combine=0 leaves t3/t5/t7/t9/rq for __pmull_4x_acc_p8 to accumulate.
	 */
	.macro		__pmull_2x_p8, rq, ad, next_key=0, combine=1
	tbl		t3.16b, {\ad\().16b}, perm1.16b
	.if		\next_key
	ldr		x6, [x4]
	.endif
	tbl		t5.16b, {\ad\().16b}, perm2.16b
	.if		\next_key
	ldr		x7, [x4, #8]
	.endif
	tbl		t7.16b, {\ad\().16b}, perm3.16b
	.if		\next_key
	ldr		x8, [x4, #24]
	.endif

	pmull2		ss1.8h, \ad\().16b, sh1.16b
	.if		\next_key
	ldr		x9, [x4, #40]
	.endif
	pmull		t4.8h, \ad\().8b, sh1.8b
	.if		\next_key
	ldr		x10, [x4, #56]
	.endif
	pmull2		ss2.8h, t3.16b, SHASH.16b
	.if		\next_key
	ldr		x11, [x4, #72]
	.endif
	pmull		t3.8h, t3.8b, SHASH.8b
	pmull2		ss3.8h, \ad\().16b, sh2.16b
	pmull		t6.8h, \ad\().8b, sh2.8b
	pmull2		ss4.8h, t5.16b, SHASH.16b
	pmull		t5.8h, t5.8b, SHASH.8b
	eor		t4.16b, t4.16b, ss1.16b
	eor		t3.16b, t3.16b, ss2.16b
	pmull2		ss1.8h, \ad\().16b, sh3.16b
	pmull		t8.8h, \ad\().8b, sh3.8b
	pmull2		ss2.8h, t7.16b, SHASH.16b
	pmull		t7.8h, t7.8b, SHASH.8b
	eor		t6.16b, t6.16b, ss3.16b
	eor		t5.16b, t5.16b, ss4.16b
	pmull2		ss3.8h, \ad\().16b, sh4.16b
	pmull		t9.8h, \ad\().8b, sh4.8b
	pmull2		ss4.8h, \ad\().16b, SHASH.16b
	pmull		\rq\().8h, \ad\().8b, SHASH.8b
	.if		\next_key
	/*
	 * The old table is dead. Pair each low-half load with an independent
	 * lane insert. LDR D clears the high half, so insert it afterwards.
	 * SHASH receives both halves from GPRs; sh1..sh4 receive their high
	 * halves from GPRs and their low halves directly from the next table.
	 */
	ldr		d20, [x4, #16]
	mov		SHASH.d[0], x6
	ldr		d21, [x4, #32]
	mov		sh1.d[1], x8
	ldr		d22, [x4, #48]
	mov		sh2.d[1], x9
	ldr		d23, [x4, #64]
	mov		sh3.d[1], x10
	mov		SHASH.d[1], x7
	mov		sh4.d[1], x11
	.endif
	eor		t8.16b, t8.16b, ss1.16b
	.if		\next_key
	add		x4, x4, #80
	.endif
	eor		t7.16b, t7.16b, ss2.16b
	eor		t9.16b, t9.16b, ss3.16b
	eor		\rq\().16b, \rq\().16b, ss4.16b
	eor		t3.16b, t3.16b, t4.16b
	eor		t5.16b, t5.16b, t6.16b
	eor		t7.16b, t7.16b, t8.16b
	.if		\combine
	__pmull_p8_combine \rq
	.endif
	.endm

	/*
	 * Reflected Montgomery reduction using byte PMULL by 0xc2.
	 * After the Karatsuba join, XL holds the low 128 product bits.
	 * Split each byte product into low (t5) and high (t6) bytes. Rotating
	 * t5 right by one byte combines adjacent products, with its wrapped
	 * byte supplying the second fold's high-byte correction. The third
	 * PMULL supplies that correction's remaining two bytes at bits 112..127.
	 * SHASH2 holds replicated 0xc2 across all two- and four-block groups.
	 */
	.macro		__pmull_reduce_p8_mul
	eor		XM.16b, XM.16b, T1.16b
	zip1		XL.2d, XL.2d, XM.2d
	zip2		XH.2d, XM.2d, XH.2d

	pmull		t3.8h, XL.8b, SHASH2.8b
	pmull2		t4.8h, XL.16b, SHASH2.16b
	eor		XH.16b, XH.16b, XL.16b
	uzp1		t5.16b, t3.16b, t4.16b
	uzp2		t6.16b, t3.16b, t4.16b
	pmull		t7.8h, t5.8b, SHASH2.8b
	ext		t5.16b, t5.16b, t5.16b, #1
	movi		t8.16b, #0
	eor		t6.16b, t6.16b, t5.16b
	ext		t7.16b, t8.16b, t7.16b, #2
	eor		XH.16b, XH.16b, t6.16b
	eor		XL.16b, XH.16b, t7.16b
	.endm

	.macro		__ghash_2x_reuse_step, reverse=0
	ld1		{T1.2d}, [x2], #16
	ld1		{NEXT.2d}, [x2], #16
	rev64		T1.16b, T1.16b
	rev64		NEXT.16b, NEXT.16b
	ext		IN1.16b, T1.16b, T1.16b, #8
	ext		NEXT.16b, NEXT.16b, NEXT.16b, #8
	eor		IN1.16b, IN1.16b, XL.16b
	zip1		T1.2d, IN1.2d, NEXT.2d
	zip2		T2.2d, IN1.2d, NEXT.2d
	eor		NEXT.16b, T1.16b, T2.16b
	.if		\reverse
	/* Cross is cached; x4 is just beyond the three 80-byte tables. */
	sub		x4, x4, #160
	__pmull_2x_p8	XM, NEXT, 1
	sub		x4, x4, #160
	__pmull_2x_p8	XH, T2, 1
	__pmull_2x_p8	XL, T1
	.else
	/* Low is cached; x4 points to the high-product table. */
	__pmull_2x_p8	XL, T1, 1
	__pmull_2x_p8	XH, T2, 1
	__pmull_2x_p8	XM, NEXT
	.endif

	eor		T2.16b, XL.16b, XH.16b
	ext		T1.16b, XL.16b, XH.16b, #8
	eor		XM.16b, XM.16b, T2.16b
	__pmull_reduce_p8_mul
	sub		x0, x0, #2
	cmp		x0, #2
	.endm


SYM_FUNC_START_LOCAL(pmull_ghash_update_p8_2x)
	cmp		x0, #2
	b.lo		pmull_ghash_update_p8
	ld1		{XL.16b}, [x1]
	__pmull_pre_p8 0
	movi		SHASH2.16b, #0xc2
	add		x4, x3, #16
	ld1		{SHASH.2d}, [x4], #16
	ld1		{sh1.2d-sh4.2d}, [x4], #64

1:
	__ghash_2x_reuse_step 0
	b.lo		2f
	__ghash_2x_reuse_step 1
	b.hs		1b
2:
	st1		{XL.16b}, [x1]
	/* A single block or odd tail uses the single-key helper. */
	cbnz		x0, pmull_ghash_update_p8
	ret
SYM_FUNC_END(pmull_ghash_update_p8_2x)

	/*
	 * Add two more 64x64 products to the unreconstructed t3/t5/t7/t9/rq
	 * terms left by __pmull_2x_p8. Only t4/t6/t8 and ss1..ss4 are scratch:
	 * the other six data registers hold inputs or completed products.
	 * Reconstruct once, after all four products have been accumulated.
	 */
	.macro		__pmull_4x_acc_p8, rq, ad, next_key=0
	tbl		ss1.16b, {\ad\().16b}, perm1.16b
	.if		\next_key
	ldr		x6, [x4]
	.endif
	tbl		ss2.16b, {\ad\().16b}, perm2.16b
	.if		\next_key
	ldr		x7, [x4, #8]
	.endif
	tbl		ss3.16b, {\ad\().16b}, perm3.16b
	.if		\next_key
	ldr		x8, [x4, #24]
	.endif
	pmull2		t4.8h, \ad\().16b, sh1.16b
	.if		\next_key
	ldr		x9, [x4, #40]
	.endif
	pmull		t6.8h, \ad\().8b, sh1.8b
	.if		\next_key
	ldr		x10, [x4, #56]
	.endif
	pmull2		t8.8h, ss1.16b, SHASH.16b
	.if		\next_key
	ldr		x11, [x4, #72]
	.endif
	pmull		ss1.8h, ss1.8b, SHASH.8b
	eor		t4.16b, t4.16b, t6.16b
	eor		t8.16b, t8.16b, ss1.16b
	pmull2		ss1.8h, \ad\().16b, sh2.16b
	pmull		t6.8h, \ad\().8b, sh2.8b
	eor		t4.16b, t4.16b, t8.16b
	pmull2		t8.8h, ss2.16b, SHASH.16b
	pmull		ss2.8h, ss2.8b, SHASH.8b
	eor		t3.16b, t3.16b, t4.16b
	eor		ss1.16b, ss1.16b, t6.16b
	eor		ss2.16b, ss2.16b, t8.16b
	pmull2		t4.8h, \ad\().16b, sh3.16b
	pmull		t6.8h, \ad\().8b, sh3.8b
	eor		ss1.16b, ss1.16b, ss2.16b
	pmull2		t8.8h, ss3.16b, SHASH.16b
	pmull		ss3.8h, ss3.8b, SHASH.8b
	eor		t5.16b, t5.16b, ss1.16b
	eor		t4.16b, t4.16b, t6.16b
	eor		ss3.16b, ss3.16b, t8.16b
	pmull2		ss1.8h, \ad\().16b, sh4.16b
	pmull		ss2.8h, \ad\().8b, sh4.8b
	pmull2		t6.8h, \ad\().16b, SHASH.16b
	pmull		t8.8h, \ad\().8b, SHASH.8b
	.if		\next_key
	/* Load the next table once the old key is dead. */
	ldr		d20, [x4, #16]
	mov		SHASH.d[0], x6
	ldr		d21, [x4, #32]
	mov		sh1.d[1], x8
	ldr		d22, [x4, #48]
	mov		sh2.d[1], x9
	ldr		d23, [x4, #64]
	mov		sh3.d[1], x10
	mov		SHASH.d[1], x7
	mov		sh4.d[1], x11
	.endif
	eor		t4.16b, t4.16b, ss3.16b
	.if		\next_key
	add		x4, x4, #80
	.endif
	eor		ss1.16b, ss1.16b, ss2.16b
	eor		t6.16b, t6.16b, t8.16b
	eor		t7.16b, t7.16b, t4.16b
	eor		t9.16b, t9.16b, ss1.16b
	eor		\rq\().16b, \rq\().16b, t6.16b
	__pmull_p8_combine \rq
	.endm

	/* (Y ^ X1)*H^4 ^ X2*H^3 ^ X3*H^2 ^ X4*H, reduced once. */
	.macro		__ghash_4x_step, reverse=0
	ld1		{t3.2d-t6.2d}, [x2], #64
	rev64		t3.16b, t3.16b
	rev64		t4.16b, t4.16b
	rev64		t5.16b, t5.16b
	rev64		t6.16b, t6.16b
	ext		t3.16b, t3.16b, t3.16b, #8
	ext		t4.16b, t4.16b, t4.16b, #8
	ext		t5.16b, t5.16b, t5.16b, #8
	ext		t6.16b, t6.16b, t6.16b, #8
	eor		t3.16b, t3.16b, XL.16b
	.if		\reverse
	/* Reverse the term pairs too, keeping the first pair in XL/XH/XM. */
	zip1		XL.2d, t5.2d, t6.2d
	zip2		XH.2d, t5.2d, t6.2d
	zip1		T1.2d, t3.2d, t4.2d
	zip2		T2.2d, t3.2d, t4.2d
	.else
	zip1		XL.2d, t3.2d, t4.2d
	zip2		XH.2d, t3.2d, t4.2d
	zip1		T1.2d, t5.2d, t6.2d
	zip2		T2.2d, t5.2d, t6.2d
	.endif
	eor		XM.16b, XL.16b, XH.16b
	eor		NEXT.16b, T1.16b, T2.16b
	.if		\reverse
	/* Walk the six tables backwards, retaining the last one for reuse. */
	sub		x4, x4, #160
	__pmull_2x_p8	XM, XM, 1, 0
	sub		x4, x4, #160
	__pmull_4x_acc_p8 XM, NEXT, 1
	sub		x4, x4, #160
	__pmull_2x_p8	XH, XH, 1, 0
	sub		x4, x4, #160
	__pmull_4x_acc_p8 XH, T2, 1
	sub		x4, x4, #160
	__pmull_2x_p8	XL, XL, 1, 0
	__pmull_4x_acc_p8 XL, T1
	.else
	__pmull_2x_p8	XL, XL, 1, 0
	__pmull_4x_acc_p8 XL, T1, 1
	__pmull_2x_p8	XH, XH, 1, 0
	__pmull_4x_acc_p8 XH, T2, 1
	__pmull_2x_p8	XM, XM, 1, 0
	__pmull_4x_acc_p8 XM, NEXT
	.endif

	eor		T2.16b, XL.16b, XH.16b
	ext		T1.16b, XL.16b, XH.16b, #8
	eor		XM.16b, XM.16b, T2.16b
	__pmull_reduce_p8_mul
	sub		x0, x0, #4
	cmp		x0, #4
	.endm

/*
 * x0: nonzero block count, x1: little-endian POLYVAL accumulator,
 * x2: GHASH input bytes, x3: struct ghash_key.
 *
 * Four-block groups share the byte-product reconstruction and reduction.
 * Alternating table traversal retains the last table for the next group.
 * Up to three remaining blocks use the two-block and single-key helpers.
 */
SYM_FUNC_START(pmull_ghash_update_p8_4x)
	cmp		x0, #4
	b.lo		pmull_ghash_update_p8_2x
	ld1		{XL.16b}, [x1]
	__pmull_pre_p8 0
	movi		SHASH2.16b, #0xc2
	/* h and h_powers_2x occupy the first 256 bytes of ghash_key. */
	add		x4, x3, #256
	ld1		{SHASH.2d}, [x4], #16
	ld1		{sh1.2d-sh4.2d}, [x4], #64
1:
	__ghash_4x_step
	b.lo		2f
	__ghash_4x_step 1
	b.hs		1b
2:
	st1		{XL.16b}, [x1]
	cbnz		x0, pmull_ghash_update_p8_2x
	ret
SYM_FUNC_END(pmull_ghash_update_p8_4x)

	.section	".rodata", "a"
	.align		6
.Lghash_neon_pack:
	/* {t3, t4}: ZIP1(t4, t3), then rotate left by one byte. */
	.byte		7, 16, 17, 18, 19, 20, 21, 22
	.byte		23, 0, 1, 2, 3, 4, 5, 6
	/* {t3, t4}: ZIP2(t4, t3), then rotate left by two bytes. */
	.byte		14, 15, 24, 25, 26, 27, 28, 29
	.byte		30, 31, 8, 9, 10, 11, 12, 13
	/* {t6, t7}: ZIP1(t6, t7), then rotate left by three bytes. */
	.byte		21, 22, 23, 0, 1, 2, 3, 4
	.byte		5, 6, 7, 16, 17, 18, 19, 20
	/* {t6, t7}: ZIP2(t6, t7), then rotate left by four bytes. */
	.byte		28, 29, 30, 31, 8, 9, 10, 11
	.byte		12, 13, 14, 15, 24, 25, 26, 27
