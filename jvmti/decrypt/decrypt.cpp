#include <stdlib.h>
#include <string.h>
 
#include <jvmti.h>
#include <jni.h>
#include <jni_md.h>
#include <openssl/aes.h>

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
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vecto

    //  AES 128-bit key
    for (int i = 0; i<16; ++i) {
    	key[i] = 32 + i;
    }
    // Set decryption key
    for (int i = 0; i<AES_BLOCK_SIZE; ++i) {
    	iv[i] = 0;
    }
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
    	fprintf(stderr, "Unable to set decryption key in AES\n");
    	exit(-1);
    }

    *new_class_data_len = class_data_len;
    jvmti_env->Allocate(class_data_len, new_class_data);
    unsigned char* my_data = *new_class_data;
    if(name&&strncmp(name,"com/monkey/",3)==0){
        // decrypt
        AES_cbc_encrypt(class_data, my_data, class_data_len, &aes, iv, AES_DECRYPT);
//        printf("class name is %s\tclass data length is =%d\tdecrypt string =%x\n",name,class_data_len, my_data));
        printf("class data length %d\n",class_data_len);
        printf("%d\n",'\0'==my_data[975]);
        int current_size=0;
        for(int start= (class_data_len - 1);start > (class_data_len-16);start--){
            if (my_data[start]!='\0'){
                current_size=start;
                printf("%d ",current_size);
                break;
            }
        }
        int kk=0;
        printf("=================\n");
        for(int k=0;k< class_data_len;k++){
            if(kk % 16 == 0){
                printf("\n");
                printf("%08X: ",kk);
            }
            printf("%002X ",my_data[k]);
            kk++;
        }
        printf("\n");
        printf("=================\n");
        realloc(my_data,current_size);

    }else{
       for (int i = 0; i < class_data_len; ++i)
           {
               my_data[i] = class_data[i];
           }
    }

//    *new_class_data_len = class_data_len;
//    jvmti_env->Allocate(class_data_len, new_class_data);
//
//    unsigned char* my_data = *new_class_data;
//
//    if(name&&strncmp(name,"com/monkey/",3)==0){
//        for (int i = 0; i < class_data_len; ++i)
//        {
//            my_data[i] = class_data[i] ;
//        }
//        printf("class name is %s\tclass data length is =%d\tdecrypt string =%d\tmy_data is %s\n",name,class_data_len, strlen((const char *)my_data),my_data);
//    }else{
//        for (int i = 0; i < class_data_len; ++i)
//        {
//            my_data[i] = class_data[i];
//        }
//    }
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