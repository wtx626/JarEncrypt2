#include "jni.h"
#include <iostream>
#include <openssl/aes.h>
#include <string.h>
 
extern"C" JNIEXPORT jbyteArray JNICALL 
Java_Encrypt_encrypt(
    JNIEnv * _env, 
    jobject _obj,
    jbyteArray _buf
){

    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char* input_string;
    unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    unsigned int length = 0;// encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;

    jsize len =_env->GetArrayLength(_buf);

    if ((len + 1) % AES_BLOCK_SIZE == 0) {
    	length = len + 1;
    }
    else {
    	length = ((len + 1)/ AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }
    printf("input string len is %d\n",length);
    // set the input string

    // set the input string
    input_string = (unsigned char*)calloc(length, sizeof(unsigned char));
    if (input_string == NULL) {
    	fprintf(stderr, "Unable to allocate memory for input_string\n");
    	exit(-1);
    }
    unsigned char* dst = (unsigned char*)_env->GetByteArrayElements(_buf, 0);
    memcpy (input_string, dst, len);
 	// Generate AES 128-bit key
    for (i = 0; i<16; ++i) {
    	key[i] = 32 + i;
    }
    // Set encryption key
    for (i = 0; i<AES_BLOCK_SIZE; ++i) {
    	iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
    	fprintf(stderr, "Unable to set encryption key in AES\n");
    	exit(-1);
    }

    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(length, sizeof(unsigned char));
    if (encrypt_string == NULL) {
    	fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
    	exit(-1);
    }
    // encrypt (iv will change)
    AES_cbc_encrypt(input_string, encrypt_string, length, &aes, iv, AES_ENCRYPT);

//    unsigned char* dst = (unsigned char*)_env->GetByteArrayElements(_buf, 0);
//
// 	for (int i = 0; i < len; ++i)
// 	{
// 		dst[i] = dst[i] ^ 0x07;
// 	}

    //重新分配数组用来存储加密之后的密文，若使用_buf存储会出现数据越界异常
    jbyteArray array = _env->NewByteArray(length) ;
    printf("encrypt length is %d \n",length);
    _env->SetByteArrayRegion(array, 0, length, (jbyte *)encrypt_string);
    return array;
}