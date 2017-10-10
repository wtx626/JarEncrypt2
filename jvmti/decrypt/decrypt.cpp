#include <stdlib.h>
#include <string.h>
 
#include <jvmti.h>
#include <jni.h>
#include <jni_md.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
typedef unsigned char uint8;

/**
 *  * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 *   * Fills in the encryption and decryption ctx objects and returns 0 on success
 *    **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];

  /*
 *    * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
 *       * nrounds is the number of times the we hash the material. More rounds are more secure but
 *          * slower.
 *             */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 *  * Encrypt *len bytes of data
 *   * All data going in & out is considered binary (unsigned char[])
 *    */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
 *     *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 *  * Decrypt *len bytes of ciphertext
 *   */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
  *len = p_len + f_len;
  return plaintext;
}

void JNICALL
MyClassFileLoadHook(
    jvmtiEnv *jvmti_env,
    JNIEnv* jni_env,
    jclass class_being_redefined,
    jobject loader,
    const char* name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data
)
{
    int olen, len;
    EVP_CIPHER_CTX en, de;
    olen = len = class_data_len ;
    unsigned int salt[] = {12345, 54321}; 
    uint8 *key_data;
    int key_data_len, i;
    key_data = "1243455566";
    key_data_len = strlen(key_data);
    /* gen key and iv. init the cipher ctx object */
    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
     }
    if(name&&strncmp(name,"com/monkey/",3)==0){
        // decrypt
        unsigned char* my_data;
       // printf("before decrypted length is %d\n",len);
	my_data = (uint8 *)aes_decrypt(&de, class_data, &len);
       // printf("decrypted length is %d\n",len);
        *new_class_data_len = len-1;
        jvmti_env->Allocate(len-1, new_class_data);
        memcpy(*new_class_data,my_data,len-1);
        free(my_data);
       // int kk=0;
       // printf("=================\n");
       // for(int k=0;k< len-1;k++){
       //     if(kk % 16 == 0){
       //         printf("\n");
       //         printf("%08X: ",kk);
       //     }
       //     printf("%002X ",my_data[k]);
       //     kk++;
       // }
       // printf("\n");
       // printf("=================\n");
        }else{
           *new_class_data_len = class_data_len;
           jvmti_env->Allocate(class_data_len, new_class_data);
           unsigned char* my_data = *new_class_data;
           for (int i = 0; i < class_data_len; ++i)
               {
                   my_data[i] = class_data[i];
               }
        }
  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);
} 
//agent是在启动时加载的
JNIEXPORT jint JNICALL
Agent_OnLoad(
    JavaVM *vm,
    char *options,
    void *reserved
)
{

    jvmtiEnv *jvmti;
    //Create the JVM TI environment(jvmti)
    jint ret = vm->GetEnv((void **)&jvmti, JVMTI_VERSION);
    if(JNI_OK!=ret)
    {
        printf("ERROR: Unable to access JVMTI!\n");
        return ret;
    }
 
    //能获取哪些能力
    jvmtiCapabilities capabilities;
    (void)memset(&capabilities,0, sizeof(capabilities));
 
    capabilities.can_generate_all_class_hook_events   = 1;
    capabilities.can_tag_objects                      = 1;
    capabilities.can_generate_object_free_events      = 1;
    capabilities.can_get_source_file_name             = 1;
    capabilities.can_get_line_numbers                 = 1;
    capabilities.can_generate_vm_object_alloc_events  = 1;
 
    jvmtiError error = jvmti->AddCapabilities(&capabilities);
    if(JVMTI_ERROR_NONE!=error)
    {
        printf("ERROR: Unable to AddCapabilities JVMTI!\n");
        return error;
    }
 
    //设置事件回调
    jvmtiEventCallbacks callbacks;
    (void)memset(&callbacks,0, sizeof(callbacks));
 
    callbacks.ClassFileLoadHook = &MyClassFileLoadHook;
    error = jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
    if(JVMTI_ERROR_NONE!=error){
        printf("ERROR: Unable to SetEventCallbacks JVMTI!\n");
        return error;
    }
    
    //设置事件通知
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
    if(JVMTI_ERROR_NONE!=error){
        printf("ERROR: Unable to SetEventNotificationMode JVMTI!\n");
        return error;
    }
 
    return JNI_OK;
}
