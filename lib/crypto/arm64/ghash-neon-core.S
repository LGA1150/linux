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

	.text

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
	pmull\t		t3.8h, t3.\nb, \bd			// F = A1*B
	pmull\t		t4.8h, \ad, \b1\().\nb			// E = A*B1
	pmull\t		t5.8h, t5.\nb, \bd			// H = A2*B
	pmull\t		t6.8h, \ad, \b2\().\nb			// G = A*B2
	pmull\t		t7.8h, t7.\nb, \bd			// J = A3*B
	pmull\t		t8.8h, \ad, \b3\().\nb			// I = A*B3
	pmull\t		t9.8h, \ad, \b4\().\nb			// K = A*B4
	pmull\t		\rq\().8h, \ad, \bd			// D = A*B

	eor		t3.16b, t3.16b, t4.16b			// L = E + F
	eor		t5.16b, t5.16b, t6.16b			// M = G + H
	eor		t7.16b, t7.16b, t8.16b			// N = I + J

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

	zip2		t5.2d, t4.2d, t3.2d
	zip1		t3.2d, t4.2d, t3.2d
	zip2		t9.2d, t6.2d, t7.2d
	zip1		t7.2d, t6.2d, t7.2d

	ext		t3.16b, t3.16b, t3.16b, #15
	ext		t5.16b, t5.16b, t5.16b, #14
	ext		t7.16b, t7.16b, t7.16b, #13
	ext		t9.16b, t9.16b, t9.16b, #12

	eor		t3.16b, t3.16b, t5.16b
	eor		t7.16b, t7.16b, t9.16b
	eor		\rq\().16b, \rq\().16b, t3.16b
	eor		\rq\().16b, \rq\().16b, t7.16b
	.endm

	.macro		__pmull_pre_p8
	ext		SHASH2.16b, SHASH.16b, SHASH.16b, #8
	eor		SHASH2.16b, SHASH2.16b, SHASH.16b

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
	tbl		sh1.16b, {SHASH.16b}, perm1.16b
	tbl		sh2.16b, {SHASH.16b}, perm2.16b
	tbl		sh3.16b, {SHASH.16b}, perm3.16b
	tbl		sh4.16b, {SHASH.16b}, T1.16b
	ext		ss1.8b, SHASH2.8b, SHASH2.8b, #1
	ext		ss2.8b, SHASH2.8b, SHASH2.8b, #2
	ext		ss3.8b, SHASH2.8b, SHASH2.8b, #3
	ext		ss4.8b, SHASH2.8b, SHASH2.8b, #4
	.endm

	.macro		__pmull_reduce_p8
	eor		XM.16b, XM.16b, T1.16b

	mov		XL.d[1], XM.d[0]
	mov		XH.d[0], XM.d[1]

	shl		T1.2d, XL.2d, #57
	shl		T2.2d, XL.2d, #62
	eor		T2.16b, T2.16b, T1.16b
	shl		T1.2d, XL.2d, #63
	eor		T2.16b, T2.16b, T1.16b
	ext		T1.16b, XL.16b, XH.16b, #8
	eor		T2.16b, T2.16b, T1.16b

	mov		XL.d[1], T2.d[0]
	mov		XH.d[0], T2.d[1]

	ushr		T2.2d, XL.2d, #1
	eor		XH.16b, XH.16b, XL.16b
	eor		XL.16b, XL.16b, T2.16b
	ushr		T2.2d, T2.2d, #6
	ushr		XL.2d, XL.2d, #1
	.endm

	/*
	 * void pmull_ghash_update_p8(size_t blocks, struct polyval_elem *dg,
	 *			      const u8 *src,
	 *			      const struct polyval_elem *h)
	 */
SYM_FUNC_START(pmull_ghash_update_p8)
	ld1		{SHASH.2d}, [x3]
	ld1		{XL.2d}, [x1]

	__pmull_pre_p8

0:	ld1		{T1.2d}, [x2], #16
	sub		x0, x0, #1

	/* multiply XL by SHASH in GF(2^128) */
	rev64		T1.16b, T1.16b

	ext		T2.16b, XL.16b, XL.16b, #8
	ext		IN1.16b, T1.16b, T1.16b, #8
	eor		T1.16b, T1.16b, T2.16b
	eor		XL.16b, XL.16b, IN1.16b

	__pmull2_p8	XH, XL, SHASH			// a1 * b1
	eor		T1.16b, T1.16b, XL.16b
	__pmull_p8 	XL, XL, SHASH			// a0 * b0
	__pmull_p8	XM, T1, SHASH2			// (a1 + a0)(b1 + b0)

	eor		T2.16b, XL.16b, XH.16b
	ext		T1.16b, XL.16b, XH.16b, #8
	eor		XM.16b, XM.16b, T2.16b

	__pmull_reduce_p8

	eor		T2.16b, T2.16b, XH.16b
	eor		XL.16b, XL.16b, T2.16b

	cbnz		x0, 0b

	st1		{XL.2d}, [x1]
	ret
SYM_FUNC_END(pmull_ghash_update_p8)

	.text

	/* Prepare the next key operand while retiring the current products. */
	.macro		__pmull_p8_4x_products, ad, p0, p1, p2, add=0, \
			lo=x6, hi=x7, cross=0, lo2=x4, hi2=x5
	tbl		v18.16b, {\ad\().16b}, v25.16b
	.if		\cross
	eor		x16, \lo, \lo, lsr #32
	.endif
	pmull		v19.8h, \ad\().8b, v9.8b
	.if		\cross
	eor		x17, \hi, \hi, lsr #32
	.endif
	pmull2		v20.8h, \ad\().16b, v9.16b
	pmull		v21.8h, \ad\().8b, v10.8b
	pmull2		v22.8h, \ad\().16b, v10.16b
	.if		\add
	eor		v19.16b, v19.16b, v20.16b
	eor		\p0\().16b, \p0\().16b, v19.16b
	.else
	eor		\p0\().16b, v19.16b, v20.16b
	.endif
	pmull		v19.8h, v18.8b, v9.8b
	pmull2		v20.8h, v18.16b, v9.16b
	.if		\cross
	fmov		s9, w16
	eor		x16, \lo2, \lo2, lsr #32
	.else
	fmov		d9, \lo
	.endif
	eor		v21.16b, v21.16b, v22.16b
	.if		\cross
	mov		v9.s[1], w17
	eor		x17, \hi2, \hi2, lsr #32
	mov		v9.s[2], w16
	.else
	mov		v9.d[1], \hi
	.endif
	pmull		v22.8h, \ad\().8b, v11.8b
	.if		\cross
	mov		v9.s[3], w17
	.else
	tbl		v10.16b, {v9.16b}, v25.16b
	.endif
	pmull2		v23.8h, \ad\().16b, v11.16b
	.if		\cross
	tbl		v10.16b, {v9.16b}, v25.16b
	.endif
	rev32		v11.8h, v9.8h
	eor		v19.16b, v19.16b, v20.16b
	.if		\add
	eor		v21.16b, v21.16b, v19.16b
	eor		\p1\().16b, \p1\().16b, v21.16b
	eor		v22.16b, v22.16b, v23.16b
	eor		\p2\().16b, \p2\().16b, v22.16b
	.else
	eor		\p1\().16b, v21.16b, v19.16b
	eor		\p2\().16b, v22.16b, v23.16b
	.endif
	.endm

	.macro		__pmull_p8_4x_reconstruct, rq
	tbl		v18.16b, {v13.16b}, v26.16b
	tbl		v19.16b, {v16.16b}, v26.16b
	tbl		v20.16b, {v13.16b}, v27.16b
	tbl		v21.16b, {v16.16b}, v27.16b
	eor		v12.16b, v12.16b, v18.16b
	eor		v15.16b, v15.16b, v19.16b
	rev64		v18.4s, v14.4s
	rev64		v19.4s, v17.4s
	eor		v12.16b, v12.16b, v20.16b
	eor		v15.16b, v15.16b, v21.16b
	eor		v14.16b, v14.16b, v18.16b
	eor		v17.16b, v17.16b, v19.16b
	tbl		v14.16b, {v14.16b}, v30.16b
	tbl		v17.16b, {v17.16b}, v30.16b
	eor		v12.16b, v12.16b, v14.16b
	eor		v15.16b, v15.16b, v17.16b
	eor		v18.16b, v12.16b, v15.16b
	ext		v19.16b, v18.16b, v18.16b, #8
	eor		v18.16b, v18.16b, v19.16b
	tbl		v18.16b, {v18.16b}, v28.16b
	eor		\rq\().16b, v12.16b, v18.16b
	.endm

	.macro		__pmull_p8_4x_cross, a, b, out
	rev64		v18.4s, \a\().4s
	rev64		v19.4s, \b\().4s
	eor		v18.16b, v18.16b, \a\().16b
	eor		v19.16b, v19.16b, \b\().16b
	uzp1		\out\().4s, v18.4s, v19.4s
	.endm

	.macro		__pmull_p8_4x_input
	ld1		{v18.16b-v21.16b}, [x2], #64
	rev64		v18.16b, v18.16b
	rev64		v19.16b, v19.16b
	rev64		v20.16b, v20.16b
	rev64		v21.16b, v21.16b
	ext		v31.16b, v31.16b, v31.16b, #8
	eor		v18.16b, v18.16b, v31.16b
	zip2		v0.2d, v18.2d, v19.2d
	zip1		v1.2d, v18.2d, v19.2d
	zip2		v2.2d, v20.2d, v21.2d
	zip1		v3.2d, v20.2d, v21.2d
	eor		v4.16b, v0.16b, v1.16b
	eor		v5.16b, v2.16b, v3.16b
	.endm

	.macro		__pmull_p8_4x_reduce
	eor		v18.16b, v6.16b, v7.16b
	ext		v19.16b, v6.16b, v7.16b, #8
	eor		v8.16b, v8.16b, v18.16b
	eor		v8.16b, v8.16b, v19.16b
	zip1		v6.2d, v6.2d, v8.2d
	zip2		v7.2d, v8.2d, v7.2d
	pmull		v18.8h, v6.8b, v29.8b
	pmull2		v19.8h, v6.16b, v29.16b
	eor		v7.16b, v7.16b, v6.16b
	uzp1		v20.16b, v18.16b, v19.16b
	uzp2		v21.16b, v18.16b, v19.16b
	ext		v20.16b, v20.16b, v20.16b, #1
	shl		v23.2d, v29.2d, #56
	pmull2		v22.8h, v20.16b, v23.16b
	eor		v21.16b, v21.16b, v20.16b
	eor		v7.16b, v7.16b, v21.16b
	eor		v31.16b, v7.16b, v22.16b
	.endm

	/*
	 * x0: block count, x1: POLYVAL accumulator, x2: GHASH input,
	 * x3: struct ghash_key (H, H^2, H^3, H^4 in POLYVAL format).
	 *
	 * x4-x7 retain the low halves of H^4 through H, x8-x11 their high
	 * halves, and x12-x15 their XORs.  x16-x17 construct the inner
	 * Karatsuba cross operands.  No stack or callee-saved GPR is used.
	 */
SYM_FUNC_START(pmull_ghash_update_p8_4x)
	cbz		x0, .Lfour_exit
	cmp		x0, #4
	b.lo		pmull_ghash_update_p8
	adr_l		x4, .Lpmull_p8_4x_masks
	ld1		{v25.16b-v28.16b}, [x4], #64
	ld1		{v30.16b}, [x4]
	add		x4, x3, #32
	ld1		{v0.16b-v1.16b}, [x4]
	ld1		{v2.16b-v3.16b}, [x3]
	zip1		v4.2d, v1.2d, v0.2d
	zip2		v5.2d, v1.2d, v0.2d
	zip1		v6.2d, v3.2d, v2.2d
	zip2		v7.2d, v3.2d, v2.2d
	eor		v8.16b, v4.16b, v5.16b
	eor		v9.16b, v6.16b, v7.16b
	umov		x4, v4.d[0]
	umov		x5, v4.d[1]
	umov		x6, v6.d[0]
	umov		x7, v6.d[1]
	umov		x8, v5.d[0]
	umov		x9, v5.d[1]
	umov		x10, v7.d[0]
	umov		x11, v7.d[1]
	umov		x12, v8.d[0]
	umov		x13, v8.d[1]
	umov		x14, v9.d[0]
	umov		x15, v9.d[1]
	ld1		{v31.16b}, [x1]
	movi		v29.16b, #0xc2
	fmov		d9, x4
	mov		v9.d[1], x5
	tbl		v10.16b, {v9.16b}, v25.16b
	rev32		v11.8h, v9.8h
.Lfour_loop:
	__pmull_p8_4x_input
	__pmull_p8_4x_cross v0, v2, v31
	__pmull_p8_4x_products v0, v12, v13, v14, 0, x6, x7
	__pmull_p8_4x_products v2, v12, v13, v14, 1, x4, x5, 1, x6, x7
	__pmull_p8_4x_products v31, v15, v16, v17, 0, x8, x9
	__pmull_p8_4x_reconstruct v6
	__pmull_p8_4x_cross v1, v3, v24
	__pmull_p8_4x_products v1, v12, v13, v14, 0, x10, x11
	__pmull_p8_4x_products v3, v12, v13, v14, 1, x8, x9, 1, x10, x11
	__pmull_p8_4x_products v24, v15, v16, v17, 0, x12, x13
	__pmull_p8_4x_reconstruct v7
	eor		v24.16b, v24.16b, v31.16b
	__pmull_p8_4x_products v4, v12, v13, v14, 0, x14, x15
	__pmull_p8_4x_products v5, v12, v13, v14, 1, x12, x13, 1, x14, x15
	__pmull_p8_4x_products v24, v15, v16, v17, 0, x4, x5
	__pmull_p8_4x_reconstruct v8
	__pmull_p8_4x_reduce
	sub		x0, x0, #4
	cmp		x0, #4
	b.hs		.Lfour_loop
	st1		{v31.16b}, [x1]
	cbnz		x0, pmull_ghash_update_p8
.Lfour_exit:
	ret
SYM_FUNC_END(pmull_ghash_update_p8_4x)

	.section	.rodata, "a"
	.align		4
.Lpmull_p8_4x_masks:
	.byte		1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
	.byte		255, 0, 1, 2, 3, 4, 5, 255, 255, 8, 9, 10, 11, 12, 13, 255
	.byte		255, 255, 255, 6, 7, 255, 255, 255, 255, 255, 255, 14, 15, 255, 255, 255
	.byte		255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 255, 255, 255, 255
	.byte		255, 255, 0, 1, 2, 3, 255, 255, 255, 255, 8, 9, 10, 11, 255, 255
