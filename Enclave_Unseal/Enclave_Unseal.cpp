/*
Unsealing enclave: Unseals data, processes transactions and reseals
*/
#include "Enclave_Unseal_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <ctype.h>
// The orignal secret used for comparison
char encrypt_data[BUFSIZ] = "Data to encrypt";
char aad_mac_text[BUFSIZ] = "No unencrypted data";

struct accountInfo{
    char *firstname;
    char *lastname ;
    double balance;
    int pin;
};
accountInfo bankInfo;

int identityVerified = 0;

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    //unseal data and store it in sealed blob
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }


    const char *convertCurText = (char*)decrypt_data;
    char t[15];
    char u[15];

    //extracting first name from string 
    long unsigned int i = 0;
    for(; i < strlen(convertCurText); i++){
        t[i] = convertCurText[i];

        if(convertCurText[i + 1] == ' '){
            break;
       }
    }
    i++;
   // memcpy(bankInfo.firstname, (char*)t, strlen(t));
    i++;

    char *fname = (char*)malloc(strlen(t) * sizeof(char));
    for(int ii = 0; ii < 15; ii++){
        if((int)t[ii] < 0 || (!isalpha(t[ii]))){
            break;
        } 
        fname[ii] = t[ii];
    }

    //extracting last name from string
    int i2 = 0;
    for(; i < strlen(convertCurText); i++){

        u[i2] = convertCurText[i];
        i2++;
        if(convertCurText[i + 1] == ' '){
            break;
       }
    }
    i++;
   // memcpy(bankInfo.lastname, u, strlen(u));
    char *lname = (char*)malloc(strlen(u) * sizeof(char));
    for(int ii = 0; ii < 10; ii++){
        if(!isalpha(u[ii])){
           break;
        } 
         lname[ii] = u[ii];
    }

    
    //extracting balance

    i2 = 0;
    for(; i < strlen(convertCurText); i++){

        u[i2] = convertCurText[i];
        i2++;
        if(convertCurText[i + 1] == ' '){
            break;
       }
    }
    i++;
    int blnce = atoi(u);
    double blnceConverted = double(blnce) / 100;
   // bankInfo.balance = (double)pn / 100;

    

    i2 = 0;
    char u2[15];
    for(; i < strlen(convertCurText); i++){

        u2[i2] = convertCurText[i];
        i2++;
        if(convertCurText[i + 1] == ' ' || convertCurText[i + 1] == '\0'){
            break;
       }
    }   
    int pin = atoi(u2);

    //inserts all info into global structure
    bankInfo = {fname, lname, blnceConverted, pin};


    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

int verifyIdentity( int pinNum){
    if(pinNum == bankInfo.pin){
        identityVerified = 1;
        return 1;
    }
    else{
        return 2;
    }
}

//concat 2 strings
char *concat(char const* str1, char const* str2) {
   size_t const l1 = strlen(str1) ;
   size_t const l2 = strlen(str2) ;

    char* result = (char*)malloc(l1 + l2 + 1);
    if(!result) return result;
    memcpy(result, str1, l1) ;
    memcpy(result + l1, str2, l2 + 1);
    return result;
}

//concat all account info
char* concatData(){
    char sp[2] = " ";
    char *space = sp;
    char *dataToEncrypt = bankInfo.firstname;
    dataToEncrypt = concat(bankInfo.firstname, space);
    dataToEncrypt = concat(dataToEncrypt, bankInfo.lastname);
    dataToEncrypt = concat(dataToEncrypt, space);

    //balance 
    double moveDec = bankInfo.balance * 100;
    int blnce = (int) moveDec;
    char *b;  

    //POINTER DEMO
    int testExam = 33;
    intToString(&b, &blnce, &testExam);
    //POINTER DEMO
    int bCheck = atoi(b);
    dataToEncrypt = concat(dataToEncrypt, b);
    //pin 
    int pin = bankInfo.pin;
    char *p;


    //POINTER DEMO
    int testExam2 = 4;
    intToString(&p, &pin, &testExam2);
    //POINTER DEMO
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

//seals updated info 
void sealUpdate(){

    char* connectedData = concatData();
    //memcpy(aad_mac_text, connectedData, strlen(connectedData));
    memcpy(encrypt_data, connectedData, strlen(connectedData));

    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));

    //will hold sealed data
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);

    sgx_status_t  ret = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);


    if (ret == SGX_SUCCESS)
    {
        char file[] = ".txt";
        char *fConcat = file;
        char *seal_file = concat(bankInfo.firstname, fConcat);
        exportSealInfo(seal_file, temp_sealed_buf, sealed_data_size);
    }
    else{
        abortPro(ret);
    }
    free(temp_sealed_buf);
}

int processTransaction(int tChoice){
    if(identityVerified == 1){
        if(tChoice == 1){// For deposits
            int dep;
            getDeposit(&dep);
            bankInfo.balance = bankInfo.balance + (double)((double)dep/100);
            sealUpdate();
            return 1;

        }
        else if(tChoice == 2){// For withdrawls
            int with;
            getWithdraw(&with);
            double withdraw = (double)with / 100;
            double allowed = bankInfo.balance - withdraw;
            if(allowed > 0){
                bankInfo.balance -= withdraw;
                sealUpdate();
                return 1;
            }
            return 0;
        }
        else if(tChoice == 3){
            printInfo(bankInfo.firstname, bankInfo.lastname, bankInfo.balance);
            return 1;
        }
        return 0;
    }
    else{
        return 0;
    }

}
