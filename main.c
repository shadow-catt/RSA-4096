  /*
 * @Author: your name
 * @Date: 2021-10-12 18:47:44
 * @LastEditTime: 2021-10-20 16:27:40
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: \RSA\RSA4096\RSA_4096_origin_private\main.c
 */
/*****************************************************************************
Filename    : main.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-9-25 11:19:48
Description : Rsa4096
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "rsa.h"
#include "keys.h"
#include "bignum.h"
void print_array(char *TAG, uint8_t *array, int len)
{
	int i;

	printf("%s[%d]: ", TAG, len);
	for(i=0; i<len; i++) {
		printf("%02X", array[i]);
	}
	printf("\n");
}

void print_array32(char* TAG, uint32_t* array, int len)
{
	int i;

	printf("%s[%d]: ", TAG, len);
	for (i = 0; i < len; i++) {
		printf("%02X", array[i]);
	}
	printf("\n");
}


const int count=1;
#define num_test 20
int private_enc_dec_test()
{
	uint8_t input[512*num_test]={0};
	rsa_pk_t pk = {0};
	rsa_sk_t sk = {0};
	uint8_t  output[512*num_test]={0};
	unsigned char msg [512*num_test]={0};
	uint32_t msg_len;
	uint32_t outputLen;
    int32_t inputLen = 0;
	printf("RSA encryption decryption test is beginning!\n");
	printf("\n");
	pk.bits = KEY_M_BITS;
	//pk.ninv = key_n_inv;
	memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
	memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
	//memcpy(&pk.n_rr            [RSA_MAX_MODULUS_LEN - sizeof(key_n_rr)], key_n_rr, sizeof(key_n_rr));
	sk.bits = KEY_M_BITS;
	memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
	memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
	memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)], key_pe, sizeof(key_pe));
	memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN-sizeof(key_p1)],   key_p1, sizeof(key_p1));
	memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN-sizeof(key_p2)],   key_p2, sizeof(key_p2));
	memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN-sizeof(key_e1)],   key_e1, sizeof(key_e1));
	memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN-sizeof(key_e2)],   key_e2, sizeof(key_e2));
	memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN-sizeof(key_c)],    key_c,  sizeof(key_c));
	sk.qinv = key_q_inv;
	sk.p_inv = key_p_inv;
	memcpy(&sk.q_rr            [(RSA_MAX_PRIME_LEN - sizeof(key_q_rr))], key_q_rr, sizeof(key_q_rr));



	
	// private key encrypt
	clock_t start,end;
	double sum=0,sum1=0;
	int status=0;
	//print_array("key_e1:",&sk.prime_exponent1,sizeof(key_e1));
	//print_array("key_e2:",&sk.prime_exponent2,sizeof(key_e2));
	//n_rr
	//print_array("n_rr", &pk.n_rr, sizeof(pk.n_rr));
	//print_array("p_e1", &pk.exponent, sizeof(key_e));
	//print_array("p_mod", &pk.modulus, sizeof(key_m));
	for(int i=0;i<count;i++)
	{
		generate_rand(input,501*num_test-1);
		inputLen = strlen((const char*)input);
		start=clock();
		status=rsa_public_encrypt_any_len(output, &outputLen, input, inputLen, &pk);
		// rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);
		end=clock();
		if(status!=0){
			printf("rsa_public_encrypt_any_len Error Code:%x\n",status);
			break;
		}		
		sum+=(double)(end-start)/CLOCKS_PER_SEC;
		start=clock();
		status=rsa_private_decrypt_any_len(msg, &msg_len, output, outputLen, &sk);
		end=clock();
		if(status!=0){
			printf("rsa_private_decrypt_any_len Error Code:%x\n",status);
			break;
		}
		sum1+=(double)(end-start)/CLOCKS_PER_SEC;
	}
	printf("rsa_public_encrypt_any_len Average time(s): %lf; rsa_private_decrypt_any_len Average time(s): %lf\n",sum/count,sum1/count);
	// print_array("input ",input,inputLen);
	// print_array("rsa_public_encrypt_any_len", output, outputLen);
	// print_array("rsa_public_decrypt_any_len", msg, msg_len);
	if(memcmp(input,msg,inputLen)!=0){
		printf("rsa_public_encrypt_any_len and rsa_private_decrypt_any_len Error\n");
		return 1;
	}
	else{
		printf("Public Encrypt and private decrypt success!\n");
	}
	return 0;
}
/*void test() {
	rsa_pk_t pk = { 0 };
	rsa_sk_t sk = { 0 };
	uint8_t  output[512 * num_test] = { 0 };
	unsigned char msg[512 * num_test] = { 0 };
	uint32_t msg_len;
	uint32_t outputLen;
	int32_t inputLen = 0;
	printf("RSA encryption decryption test is beginning!\n");
	printf("\n");
	pk.bits = KEY_M_BITS;
	pk.ninv = key_q_inv;
	//memcpy(&pk.modulus[RSA_MAX_MODULUS_LEN - sizeof(key_m)], key_m, sizeof(key_m));
	//memcpy(&pk.exponent[RSA_MAX_MODULUS_LEN - sizeof(key_e)], key_e, sizeof(key_e));
	memcpy(&pk.n_rr[RSA_MAX_MODULUS_LEN - sizeof(key_q_rr)], key_q_rr, sizeof(key_q_rr));
	sk.bits = KEY_M_BITS;
	//memcpy(&sk.modulus[RSA_MAX_MODULUS_LEN - sizeof(key_m)], key_m, sizeof(key_m));
	//memcpy(&sk.public_exponet[RSA_MAX_MODULUS_LEN - sizeof(key_e)], key_e, sizeof(key_e));
	//memcpy(&sk.exponent[RSA_MAX_MODULUS_LEN - sizeof(key_pe)], key_pe, sizeof(key_pe));
	//memcpy(&sk.prime1[RSA_MAX_PRIME_LEN - sizeof(key_p1)], key_p1, sizeof(key_p1));
	memcpy(&sk.prime2[RSA_MAX_PRIME_LEN - sizeof(key_p2)], key_p2, sizeof(key_p2));
	//memcpy(&sk.prime_exponent1[RSA_MAX_PRIME_LEN - sizeof(key_p2)], key_p2, sizeof(key_p2));
	//memcpy(&sk.prime_exponent2[RSA_MAX_PRIME_LEN - sizeof(key_e2)], key_e2, sizeof(key_e2));
	//memcpy(&sk.coefficient[RSA_MAX_PRIME_LEN - sizeof(key_c)], key_c, sizeof(key_c));

	bn_t rr[128] = { 0 };
	uint32_t a[128] = { 12,0,3432,34243,423432,0,12312 }, modulus[512] = { 0 }, c[512] = { 0 }, d[128] = { 0 };
	bn_decode(rr, BN_MAX_DIGITS, pk.n_rr, RSA_MAX_MODULUS_LEN);
	bn_decode(modulus, BN_MAX_DIGITS, sk.prime2 , RSA_MAX_MODULUS_LEN);
	print_array32("modulus", modulus, sizeof(key_p2));
	bn_t one[128] = {0};
	bn_assign_one(one, 128);
	
	montMul(c, a, rr, modulus, 128, pk.ninv);//aR
	montMul(d, c, one, modulus, 128, pk.ninv);

}*/
int main(int argc, char const *argv[])
{
	private_enc_dec_test();
	// public_enc_dec();
	//public_block_operation();
	//test();
}
