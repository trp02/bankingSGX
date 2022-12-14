/*
Sealing enclave: Takes primary info about new user and seals it

*/
#include "sgx_eid.h"
#include <cstdlib>
#include <stdlib.h>
#include <stdio.h>
#include <sgx_key.h>
#include "Enclave_Seal_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <string.h>
char encrypt_data[BUFSIZ] = "Data to encrypt";
char aad_mac_text[BUFSIZ] = "No unencrypted data";

struct accountInfo *bankInfo;


uint32_t get_sealed_data_size()
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
}

sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    
    //SEAL DATA API USES MRSIGNER
    sgx_status_t  err = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }
    free(temp_sealed_buf);
    
    return err;
}

//Foreign functions start

char *concat(char const* str1, char const* str2) {
   size_t const l1 = strlen(str1) ;
   size_t const l2 = strlen(str2) ;

    char* result = (char*)malloc(l1 + l2 + 1);
    if(!result) return result;
    memcpy(result, str1, l1) ;
    memcpy(result + l1, str2, l2 + 1);
    return result;
}

//Concats string->OCALL to turn double/int into string, checks if double/int were manipulated
char* concatData(){
    char sp[2] = " ";
    char *space = sp;
    char *dataToEncrypt = bankInfo->firstname;
    dataToEncrypt = concat(bankInfo->firstname, space);
    dataToEncrypt = concat(dataToEncrypt, bankInfo->lastname);
    dataToEncrypt = concat(dataToEncrypt, space);

    //balance 
    double moveDec = bankInfo->balance * 100;
    int blnce = (int) moveDec;
    char *b;  
    int testExam;
    intToString(&b, &blnce, &testExam);
    int bCheck = atoi(b);

    dataToEncrypt = concat(dataToEncrypt, b);

    //pin 
    int pin = bankInfo->pin;
    char *p;
    intToString(&p, &pin, &testExam);
    int pCheck = atoi(p);
    dataToEncrypt = concat(dataToEncrypt, space);
    dataToEncrypt = concat(dataToEncrypt, p);
    dataToEncrypt = concat(dataToEncrypt, space);

    //error check pin and balance
    if(blnce != bCheck || pin != pCheck){
        char failed[] = "Data processing failed.";
        char *ret = failed;
        return ret;
    }
    return dataToEncrypt;
}

//records new user and encrypts data
//concats it all together and sends to be sealed
char* storeNewUser(struct accountInfo *user){

    bankInfo = user;
    char *ret =concatData();
    char f[] = "Data processing failed";
    char *failed = f;
    if(strcmp(failed, ret) == 0){
        return failed;
    }
    memcpy(encrypt_data, ret, strlen(ret));
    uint32_t sealed_data_size = 0;

    //get sealed data blob
    sealed_data_size = get_sealed_data_size();
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    seal_data(temp_sealed_buf, sealed_data_size);

    
    char file[] = ".txt";
    char *fConcat = file;
    char *seal_file = concat(bankInfo->firstname, fConcat);
    exportSealInfo(seal_file, temp_sealed_buf, sealed_data_size);

    return ret;
   
}


