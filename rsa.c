/*****************************************************************************
Filename    : rsa.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-9-25 11:19:56
Description :
*****************************************************************************/
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "rsa.h"
#include "bignum.h"

static int private_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);

int rsa_private_encrypt_any_len(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk){
	int status=0;
	int len=0;
	uint8_t *tmp_o=out;
	*out_len=0;
	for(int i=0;i<in_len && status==0;i+=(RSA_MAX_MODULUS_LEN-11)){
		if((in_len-i)>(RSA_MAX_MODULUS_LEN-11)){
			status=rsa_private_encrypt(tmp_o,&len,in+i,RSA_MAX_MODULUS_LEN-11,sk);
		}
		else{
			status=rsa_private_encrypt(tmp_o,&len,in+i,in_len-i,sk);
			break;
		}
		tmp_o=tmp_o+len;
		*out_len+=len;
	}
	tmp_o=NULL;
	free(tmp_o);
	return status;
}

int rsa_public_encrypt_any_len(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk){
	int status=0;
	int len=0;
	uint8_t *tmp_o=out;
	*out_len=0;
	for(int i=0;i<in_len && status==0;i+=(RSA_MAX_MODULUS_LEN-11)){
		if((in_len-i)>(RSA_MAX_MODULUS_LEN-11)){
			status=rsa_public_encrypt(tmp_o,&len,in+i,RSA_MAX_MODULUS_LEN-11,pk);
			tmp_o=tmp_o+len;
			*out_len+=len;
		}
		else{
			status=rsa_public_encrypt(tmp_o,&len,in+i,in_len-i,pk);
			*out_len+=len;
			break;
		}		
	}
	tmp_o=NULL;
	free(tmp_o);
	// *out_len=len;
	return status;
}


int rsa_private_decrypt_any_len(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk){
	int status=0;
	int len=0;
	uint8_t *tmp_o=out;
	int i=0;
	*out_len=0;
	for(i=0;i<in_len && status==0;i+=RSA_MAX_MODULUS_LEN){
		if((in_len-i)>RSA_MAX_MODULUS_LEN){
			status=rsa_private_decrypt(tmp_o,&len,in+i,RSA_MAX_MODULUS_LEN,sk);
			tmp_o=tmp_o+len;
			*out_len+=len;
		}
		else{
			status=rsa_private_decrypt(tmp_o,&len,in+i,in_len-i,sk);
			*out_len+=len;
			break;
		}
		
	}
	tmp_o=NULL;
	free(tmp_o);
	return status;
}

int rsa_private_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (sk->bits + 7) / 8;
    if(in_len + 11 > modulus_len)
        return ERR_WRONG_LEN;

    pkcs_block[0] = 0;
    pkcs_block[1] = 1;
    for(i=2; i<modulus_len-in_len-1; i++) {
        pkcs_block[i] = 0xFF;
    }

    pkcs_block[i++] = 0;

    memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);

    status = private_block_operation(out, out_len, pkcs_block, modulus_len, sk);

    // Clear potentially sensitive information
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

int rsa_private_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len, pkcs_block_len;

    modulus_len = (sk->bits + 7) / 8;
    /*if(in_len > modulus_len)
        return ERR_WRONG_LEN;*/

    status = private_block_operation(pkcs_block, &pkcs_block_len, in, in_len, sk);
    /*if(status != 0)
        return status;*/

    if(pkcs_block_len != modulus_len)
        return ERR_WRONG_LEN;

    /*if((pkcs_block[0] != 0) || (pkcs_block[1] != 2))
        return ERR_WRONG_DATA;*/

    for(i=2; i<modulus_len-1; i++) {
        if(pkcs_block[i] == 0)  break;
    }

    i++;
    /*if(i >= modulus_len)
        return ERR_WRONG_DATA;
    *out_len = modulus_len - i;
    if(*out_len + 11 > modulus_len)
        return ERR_WRONG_DATA;*/
    memcpy((uint8_t *)out, (uint8_t *)&pkcs_block[i], *out_len);
    // Clear potentially sensitive information
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

static int private_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    uint32_t cdigits, ndigits, pdigits,qq_inv,p_inv;
    bn_t c[BN_MAX_DIGITS], cp[BN_MAX_DIGITS], cq[BN_MAX_DIGITS];
    bn_t dp[BN_MAX_DIGITS], dq[BN_MAX_DIGITS], mp[BN_MAX_DIGITS], mq[BN_MAX_DIGITS];
    bn_t n[BN_MAX_DIGITS], p[BN_MAX_DIGITS], q[BN_MAX_DIGITS], q_inv[BN_MAX_DIGITS], t[BN_MAX_DIGITS],q_rr[BN_MAX_DIGITS];

    bn_decode(c, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, sk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(p, BN_MAX_DIGITS, sk->prime1, RSA_MAX_PRIME_LEN);
    bn_decode(q, BN_MAX_DIGITS, sk->prime2, RSA_MAX_PRIME_LEN);
    bn_decode(dp, BN_MAX_DIGITS, sk->prime_exponent1, RSA_MAX_PRIME_LEN);
    bn_decode(dq, BN_MAX_DIGITS, sk->prime_exponent2, RSA_MAX_PRIME_LEN);
    bn_decode(q_inv, BN_MAX_DIGITS, sk->coefficient, RSA_MAX_PRIME_LEN);
    bn_decode(q_rr, BN_MAX_DIGITS, sk->q_rr, RSA_MAX_PRIME_LEN);
    

    /*print_array("p", p, sizeof(sk->prime1));
    print_array("q", q, sizeof(sk->prime2));
    print_array("q_rr", q_rr, sizeof(sk->q_rr));*/

    p_inv = sk->p_inv;
    cdigits = bn_digits(c, BN_MAX_DIGITS);
    ndigits = bn_digits(n, BN_MAX_DIGITS);
    pdigits = bn_digits(p, BN_MAX_DIGITS);
    qq_inv = sk->qinv;
    //printf("%x", qq_inv);
    if(bn_cmp(c, n, ndigits) >= 0)
        return ERR_WRONG_DATA;

    bn_mod(cp, c, cdigits, p, pdigits);
    bn_mod(cq, c, cdigits, q, pdigits);
    bn_mod_exp(mp, cp, dp, pdigits, p, pdigits);
   
    bn_assign_zero(mq, ndigits);


    bn_t one[128] = { 0 };
    bn_assign_one(one, 128);
    uint32_t a[128] = { 12,0,3432,34243,423432,0,12312 }, modulus[512] = { 0 }, e[512] = { 0 }, d[128] = { 0 };
    montMul(e, cq, q_rr, q, 128, qq_inv); 
    montMul(d, e, one, q, 128, qq_inv);


    //����

    bn_mod_exp(mq, cq, dq, pdigits, q, pdigits);
    //Bn_mod_exp(mq,cq,dq,pdigits,q,pdigits,qq_inv,q_rr);


    if(bn_cmp(mp, mq, pdigits) >= 0) {
        bn_sub(t, mp, mq, pdigits);
    } else {
        bn_sub(t, mq, mp, pdigits);
        bn_sub(t, p, t, pdigits);
    }

    bn_mod_mul(t, t, q_inv, p, pdigits);
    //print_array("t", t, sizeof(sk->prime1));
   // montMul(mp, t, q_inv, p, pdigits, p_inv);
    //print_array("mp", mp, sizeof(sk->prime1));
    bn_mul(t, t, q, pdigits);
    bn_add(t, t, mq, ndigits);

    *out_len = (sk->bits + 7) / 8;
    bn_encode(out, *out_len, t, ndigits);

    // Clear potentially sensitive information
    memset((uint8_t *)c, 0, sizeof(c));
    memset((uint8_t *)cp, 0, sizeof(cp));
    memset((uint8_t *)cq, 0, sizeof(cq));
    memset((uint8_t *)dp, 0, sizeof(dp));
    memset((uint8_t *)dq, 0, sizeof(dq));
    memset((uint8_t *)mp, 0, sizeof(mp));
    memset((uint8_t *)mq, 0, sizeof(mq));
    memset((uint8_t *)p, 0, sizeof(p));
    memset((uint8_t *)q, 0, sizeof(q));
    memset((uint8_t *)q_inv, 0, sizeof(q_inv));
    memset((uint8_t *)t, 0, sizeof(t));

    return 0;
}

// Public encryption
static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);

void generate_rand(uint8_t *block, uint32_t block_len)
{
    uint32_t i;
	srand ((unsigned)time(NULL));   // real rand message
    for(i=0; i<block_len; i++) {
        block[i] = rand();
		while(block[i]==0)
			block[i]=rand();
    }
}


// int rsa_public_decrypt_any_len(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk){
// 	int status=0;
// 	int len=0;
// 	uint8_t *tmp_o=out;
// 	*out_len=0;
// 	for(int i=0;i<in_len && status==0;i+=RSA_MAX_MODULUS_LEN){
// 		if((in_len-i)>RSA_MAX_MODULUS_LEN){
// 			status=rsa_public_decrypt(tmp_o,&len,in,RSA_MAX_MODULUS_LEN,pk);
// 		}
// 		else{
// 			status=rsa_public_decrypt(tmp_o,&len,in,in_len-i,pk);
// 			break;
// 		}
// 		tmp_o=tmp_o+len;
// 		*out_len+=len;
// 	}
// 	tmp_o=NULL;
// 	free(tmp_o);
// 	// *out_len=len;
// 	return status;
// }

int rsa_public_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint8_t byte, pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len + 11 > modulus_len) {//padding len
        return ERR_WRONG_LEN;
    }

    pkcs_block[0] = 0;
    pkcs_block[1] = 2;
    for(i=2; i<modulus_len-in_len-1; i++) {
        do {
            generate_rand(&byte, 1);
        } while(byte == 0);
        pkcs_block[i] = byte;
    }
    pkcs_block[i++] = 0;

    memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);
    status = public_block_operation(out, out_len, pkcs_block, modulus_len, pk);
    // Clear potentially sensitive information
    byte = 0;
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

// int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk) {
//     int status;
//     uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
//     uint32_t i, modulus_len, pkcs_block_len;

//     modulus_len = (pk->bits + 7) / 8;
//     if (in_len > modulus_len)
//         return ERR_WRONG_LEN;

//     status = public_block_operation(pkcs_block, &pkcs_block_len, in, in_len, pk);
//     if (status != 0)
//         return status;

//     if (pkcs_block_len != modulus_len)
//         return ERR_WRONG_LEN;

//     if ((pkcs_block[0] != 0) || (pkcs_block[1] != 1))
//         return ERR_WRONG_DATA;

//     for (i = 2; i < modulus_len - 1; i++) {
//         if (pkcs_block[i] != 0xFF) break;
//     }

//     if (pkcs_block[i++] != 0)
//         return ERR_WRONG_DATA;

//     *out_len = modulus_len - i;
//     if (*out_len + 11 > modulus_len)
//         return ERR_WRONG_DATA;

//     memcpy((uint8_t *) out, (uint8_t *) &pkcs_block[i], *out_len);

//     // Clear potentially sensitive information
//     memset((uint8_t *) pkcs_block, 0, sizeof(pkcs_block));

//     return status;
// }

static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    uint32_t edigits, ndigits,inv;
    bn_t c[BN_MAX_DIGITS], e[BN_MAX_DIGITS], m[BN_MAX_DIGITS], n[BN_MAX_DIGITS],rr[BN_MAX_DIGITS];

    bn_decode(m, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, pk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(e, BN_MAX_DIGITS, pk->exponent, RSA_MAX_MODULUS_LEN);
    bn_decode(rr, BN_MAX_DIGITS, pk->n_rr, RSA_MAX_MODULUS_LEN);
    
    inv = pk->ninv;
    ndigits = bn_digits(n, BN_MAX_DIGITS);
    edigits = bn_digits(e, BN_MAX_DIGITS);

    if(bn_cmp(m, n, ndigits) >= 0) {
        return ERR_WRONG_DATA;
    }

    bn_t c_real[BN_MAX_DIGITS];
    bn_decode(c_real, BN_MAX_DIGITS, c, RSA_MAX_MODULUS_LEN);
    int si;
    bn_mod_exp(c, m, e, edigits, n, ndigits);


    //Bn_mod_exp(c_real,m,e,edigits,n,ndigits,inv,rr);

    si = bn_cmp(c, c_real, BN_MAX_DIGITS);
    printf("");

    *out_len = (pk->bits + 7) / 8;
    bn_encode(out, *out_len, c, ndigits);

    // Clear potentially sensitive information
    memset((uint8_t *)c, 0, sizeof(c));
    memset((uint8_t *)m, 0, sizeof(m));

    return 0;
}

