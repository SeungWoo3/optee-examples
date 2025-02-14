/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2023, NVIDIA Corporation & AFFILIATES.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The original source is from optee_os/core/lib/libtomcrypt/src/mpi_desc.c
 */

#include <mbedtls/bignum.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt_private.h>
#include <util.h>

/* From mbedtls/library/bignum.c */
#define ciL		(sizeof(mbedtls_mpi_uint))	/* chars in limb  */
#define biL		(ciL << 3)			/* bits  in limb  */
#define BITS_TO_LIMBS(i)	((i) / biL + ((i) % biL != 0))

static int init(void **a)
{
    mbedtls_mpi *bn = calloc(1, sizeof(*bn));

    if (!bn)
        return CRYPT_MEM;

    mbedtls_mpi_init(bn);
    *a = bn;

    return CRYPT_OK;
}

static int init_size(int size_bits __unused, void **a)
{
    return init(a);
}

static void deinit(void *a)
{
    mbedtls_mpi_free((mbedtls_mpi *)a);
    free(a);
}

static int neg(void *a, void *b)
{
    if (mbedtls_mpi_copy(b, a))
        return CRYPT_MEM;

    ((mbedtls_mpi *)b)->s *= -1;

    return CRYPT_OK;
}

static int copy(void *a, void *b)
{
    if (mbedtls_mpi_copy(b, a))
        return CRYPT_MEM;

    return CRYPT_OK;
}

static int init_copy(void **a, void *b)
{
    if (init(a) != CRYPT_OK) {
        return CRYPT_MEM;
    }

    return copy(b, *a);
}

/* ---- trivial ---- */
static int set_int(void *a, ltc_mp_digit b)
{
    uint32_t b32 = b;

    if (b32 != b)
        return CRYPT_INVALID_ARG;

    mbedtls_mpi_uint p = b32;
    mbedtls_mpi bn = { .s = 1, .n = 1, .p = &p };

    if (mbedtls_mpi_copy(a, &bn))
        return CRYPT_MEM;

    return CRYPT_OK;
}

static unsigned long get_int(void *a)
{
    mbedtls_mpi *bn = a;

    if (!bn->n)
        return 0;

    return bn->p[bn->n - 1];
}

static ltc_mp_digit get_digit(void *a, int n)
{
    mbedtls_mpi *bn = a;

    COMPILE_TIME_ASSERT(sizeof(ltc_mp_digit) >= sizeof(mbedtls_mpi_uint));

    if (n < 0 || (size_t)n >= bn->n)
        return 0;

    return bn->p[n];
}

static int get_digit_count(void *a)
{
    return ROUNDUP(mbedtls_mpi_size(a), sizeof(mbedtls_mpi_uint)) /
           sizeof(mbedtls_mpi_uint);
}

static int compare(void *a, void *b)
{
    int ret = mbedtls_mpi_cmp_mpi(a, b);

    if (ret < 0)
        return LTC_MP_LT;

    if (ret > 0)
        return LTC_MP_GT;

    return LTC_MP_EQ;
}

static int compare_d(void *a, ltc_mp_digit b)
{
    unsigned long v = b;
    unsigned int shift = 31;
    uint32_t mask = BIT(shift) - 1;
    mbedtls_mpi bn;

    mbedtls_mpi_init(&bn);
    while (true) {
        mbedtls_mpi_add_int(&bn, &bn, v & mask);
        v >>= shift;
        if (!v)
            break;
        mbedtls_mpi_shift_l(&bn, shift);
    }

    int ret = compare(a, &bn);

    mbedtls_mpi_free(&bn);

    return ret;
}

static int count_bits(void *a)
{
    return mbedtls_mpi_bitlen(a);
}

static int count_lsb_bits(void *a)
{
    return mbedtls_mpi_lsb(a);
}

static int twoexpt(void *a, int n)
{
    if (mbedtls_mpi_set_bit(a, n, 1))
        return CRYPT_MEM;

    return CRYPT_OK;
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
    return mbedtls_mpi_size(a);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
    int res = mbedtls_mpi_write_binary(a, b, unsigned_size(a));

    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
        return CRYPT_MEM;
    if (res)
        return CRYPT_ERROR;

    return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
    int res = mbedtls_mpi_read_binary(a, b, len);

    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
        return CRYPT_MEM;
    if (res)
        return CRYPT_ERROR;

    return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
    if (mbedtls_mpi_add_mpi(c, a, b))
        return CRYPT_MEM;

    return CRYPT_OK;
}

static int addi(void *a, ltc_mp_digit b, void *c)
{
    uint32_t b32 = b;

    if (b32 != b)
        return CRYPT_INVALID_ARG;

    mbedtls_mpi_uint p = b32;
    mbedtls_mpi bn = { .s = 1, .n = 1, .p = &p };

    return add(a, &bn, c);
}

/* sub */
static int sub(void *a, void *b, void *c)
{
    if (mbedtls_mpi_sub_mpi(c, a, b))
        return CRYPT_MEM;

    return CRYPT_OK;
}

static int subi(void *a, ltc_mp_digit b, void *c)
{
    uint32_t b32 = b;

    if (b32 != b)
        return CRYPT_INVALID_ARG;

    mbedtls_mpi_uint p = b32;
    mbedtls_mpi bn = { .s = 1, .n = 1, .p = &p };

    return sub(a, &bn, c);
}

/* mul */
static int mul(void *a, void *b, void *c)
{
    if (mbedtls_mpi_mul_mpi(c, a, b))
        return CRYPT_MEM;

    return CRYPT_OK;
}

static int muli(void *a, ltc_mp_digit b, void *c)
{
    if (b > (unsigned long) UINT32_MAX)
        return CRYPT_INVALID_ARG;

    if (mbedtls_mpi_mul_int(c, a, b))
        return CRYPT_MEM;

    return CRYPT_OK;
}

/* sqr */
static int sqr(void *a, void *b)
{
    return mul(a, a, b);
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
    int res = mbedtls_mpi_div_mpi(c, d, a, b);

    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
        return CRYPT_MEM;
    if (res)
        return CRYPT_ERROR;

    return CRYPT_OK;
}

static int div_2(void *a, void *b)
{
    if (mbedtls_mpi_copy(b, a))
        return CRYPT_MEM;

    if (mbedtls_mpi_shift_r(b, 1))
        return CRYPT_MEM;

    return CRYPT_OK;
}

/* modi */
static int modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
    mbedtls_mpi bn_b;
    mbedtls_mpi bn_c;
    int res = 0;

    mbedtls_mpi_init(&bn_b);
    mbedtls_mpi_init(&bn_c);

    res = set_int(&bn_b, b);
    if (res)
        return res;

    res = mbedtls_mpi_mod_mpi(&bn_c, &bn_b, a);
    if (!res)
        *c = get_int(&bn_c);

    mbedtls_mpi_free(&bn_b);
    mbedtls_mpi_free(&bn_c);

    if (res)
        return CRYPT_MEM;

    return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
    if (mbedtls_mpi_gcd(c, a, b))
        return CRYPT_MEM;

    return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
    int res = CRYPT_MEM;
    mbedtls_mpi tmp;

    mbedtls_mpi_init(&tmp);
    if (mbedtls_mpi_mul_mpi(&tmp, a, b))
        goto out;

    if (mbedtls_mpi_gcd(c, a, b))
        goto out;

    /* We use the following equality: gcd(a, b) * lcm(a, b) = a * b */
    res = divide(&tmp, c, c, NULL);
out:
    mbedtls_mpi_free(&tmp);

    return res;
}

static int mod(void *a, void *b, void *c)
{
    int res = mbedtls_mpi_mod_mpi(c, a, b);

    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
        return CRYPT_MEM;
    if (res)
        return CRYPT_ERROR;

    return CRYPT_OK;
}

static int addmod(void *a, void *b, void *c, void *d)
{
    int res = add(a, b, d);

    if (res)
        return res;

    return mod(d, c, d);
}

static int submod(void *a, void *b, void *c, void *d)
{
    int res = sub(a, b, d);

    if (res)
        return res;

    return mod(d, c, d);
}

static int mulmod(void *a, void *b, void *c, void *d)
{
    int res;
    mbedtls_mpi ta;
    mbedtls_mpi tb;

    mbedtls_mpi_init(&ta);
    mbedtls_mpi_init(&tb);

    res = mod(a, c, &ta);
    if (res)
        goto out;
    res = mod(b, c, &tb);
    if (res)
        goto out;
    res = mul(&ta, &tb, d);
    if (res)
        goto out;
    res = mod(d, c, d);
out:
    mbedtls_mpi_free(&ta);
    mbedtls_mpi_free(&tb);

    return res;
}

static int sqrmod(void *a, void *b, void *c)
{
    return mulmod(a, a, b, c);
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
    int res = mbedtls_mpi_inv_mod(c, a, b);

    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
        return CRYPT_MEM;
    if (res)
        return CRYPT_ERROR;

    return CRYPT_OK;
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
    *b = calloc(1, sizeof(mbedtls_mpi_uint));
    if (!*b)
        return CRYPT_MEM;

    mbedtls_mpi_montg_init(*b, a);

    return CRYPT_OK;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
    size_t c = ROUNDUP(mbedtls_mpi_size(b), sizeof(mbedtls_mpi_uint)) * 8;

    if (mbedtls_mpi_lset(a, 1))
        return CRYPT_MEM;
    if (mbedtls_mpi_shift_l(a, c))
        return CRYPT_MEM;
    if (mbedtls_mpi_mod_mpi(a, a, b))
        return CRYPT_MEM;

    return CRYPT_OK;
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
    mbedtls_mpi A;
    mbedtls_mpi *N = b;
    mbedtls_mpi_uint *mm = c;
    mbedtls_mpi T;
    int ret = CRYPT_MEM;

    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&A);

    if (mbedtls_mpi_grow(&T, (N->n + 1) * 2))
        goto out;

    if (mbedtls_mpi_cmp_mpi(a, N) > 0) {
        if (mbedtls_mpi_mod_mpi(&A, a, N))
            goto out;
    } else {
        if (mbedtls_mpi_copy(&A, a))
            goto out;
    }

    if (mbedtls_mpi_grow(&A, N->n + 1))
        goto out;

    mbedtls_mpi_montred(&A, N, *mm, &T);

    if (mbedtls_mpi_copy(a, &A))
        goto out;

    ret = CRYPT_OK;
out:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&T);

    return ret;
}

/* clean up */
static void montgomery_deinit(void *a)
{
    free(a);
}

/*
 * This function calculates:
 *  d = a^b mod c
 *
 * @a: base
 * @b: exponent
 * @c: modulus
 * @d: destination
 */
static int exptmod(void *a, void *b, void *c, void *d)
{
    int res;

    if (d == a || d == b || d == c) {
        mbedtls_mpi dest;

        mbedtls_mpi_init(&dest);
        res = mbedtls_mpi_exp_mod(&dest, a, b, c, NULL);
        if (!res)
            res = mbedtls_mpi_copy(d, &dest);
        mbedtls_mpi_free(&dest);
    } else {
        res = mbedtls_mpi_exp_mod(d, a, b, c, NULL);
    }

    if (res)
        return CRYPT_MEM;
    else
        return CRYPT_OK;
}

ltc_math_descriptor ltc_mp = {
    .name = "MPI",
    .bits_per_digit = sizeof(mbedtls_mpi_uint) * 8,

    .init = init,
    .init_size = init_size,
    .init_copy = init_copy,
    .deinit = deinit,

    .neg = neg,
    .copy = copy,

    .set_int = set_int,
    .get_int = get_int,
    .get_digit = get_digit,
    .get_digit_count = get_digit_count,
    .compare = compare,
    .compare_d = compare_d,
    .count_bits = count_bits,
    .count_lsb_bits = count_lsb_bits,
    .twoexpt = twoexpt,

    .unsigned_size = unsigned_size,
    .unsigned_write = unsigned_write,
    .unsigned_read = unsigned_read,

    .add = add,
    .addi = addi,
    .sub = sub,
    .subi = subi,
    .mul = mul,
    .muli = muli,
    .sqr = sqr,
    .mpdiv = divide,
    .div_2 = div_2,
    .modi = modi,
    .gcd = gcd,
    .lcm = lcm,

    .mulmod = mulmod,
    .sqrmod = sqrmod,
    .invmod = invmod,

    .montgomery_setup = montgomery_setup,
    .montgomery_normalization = montgomery_normalization,
    .montgomery_reduce = montgomery_reduce,
    .montgomery_deinit = montgomery_deinit,

    .exptmod = exptmod,

#ifdef LTC_MECC
    .ecc_ptmul = ltc_ecc_mulmod,
    .ecc_ptadd = ltc_ecc_projective_add_point,
    .ecc_ptdbl = ltc_ecc_projective_dbl_point,
    .ecc_map = ltc_ecc_map,

    .ecc_mul2add = ltc_ecc_mul2add,
#endif /* LTC_MECC */

    .addmod = addmod,
    .submod = submod,
};
