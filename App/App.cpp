
// App.cpp : Define the entry point for the console application.

#include <execinfo.h>
#include "App.h"
#include <string.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "sgx_urts.h"
#include "Enclave_Seal_u.h"
#include "Enclave_Unseal_u.h"

#include "ErrorSupport.h"
using namespace std;
#define SEALED_DATA_FILE "sealed_data_blob.txt"

//file I/O functions start
 size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

 bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

 bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}
//file I/O functions end

// Initialize the enclave:
//   Call sgx_create_enclave to initialize an enclave instance
 sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // Call sgx_create_enclave to initialize an enclave instance
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("failed to load enclave %s, error code is 0x%x.\n", enclave_path, ret);
        return ret;
    }

    return SGX_SUCCESS;
}



//Added Functions
void exportSealInfo(char *fileName, uint8_t *buf, uint32_t data_size){
    if(write_buf_to_file(fileName, buf, data_size, 0) == false){
        cout << "SEALING FAILED" << endl;
    }
}

//gets initial info and sends to enclave to be encrypted
 void getInitialInfo(){
    
    accountInfo newUser;
    printf("First Name: ");
    cin >> newUser.firstname;
    printf("Last name: ");
    cin >> newUser.lastname;
    printf("Pick a 4 digit pin: ");
    cin >> newUser.pin;
    printf("Initial deposit: ");
    cin >> newUser.balance;

    sgx_enclave_id_t eid_seal = 0;


    initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);

    char *retval;

    storeNewUser(eid_seal, &retval ,&newUser);
    sgx_destroy_enclave(eid_seal);

 }

void printPin(int *pin){
    printf("PIN: %p  %d\n", pin, *pin);
}

char *intToString(int *num, int *num2){

    //MEMORY 
    *num2 = 55;
    void *aa[15];
    char**ss; 
    int nn = backtrace(aa, 15);
    ss = backtrace_symbols(aa, nn);
    for(int i = 0; i < nn; i++){
        printf("OCALL ADDRESSES %s\n", ss[i]);

    }
    int untrustedVar = 0;
    printf("UNTRUSTED VAR ADDRES: %p\n", &untrustedVar);
    printf("MARSHALED POINTER   : %p\n", num);
    printf("NON-MARSHALED PNTR  : %p\n\n\n",num2);
    //MEMORY 

    
    int convert = *num;
    char ret[15];
    sprintf(ret, "%d", convert);
    char *x = ret;
    return x;
}

//user choses transaction
int transactionUI(){

    printf("\n0. Exit application\n");
    printf("1. Deposit money\n");
    printf("2. Withdraw money\n");
    printf("3. Display account information\n");
    printf("Choose an option: ");
    int choice;
    scanf("%d", &choice);
    if(choice >= 0 && choice <= 3){
        return choice;
    }
    else{
        printf("Not a valid option, try again.\n");
        return transactionUI();
    }

}

//pulls up returning user info
void returningUser(){

    sgx_enclave_id_t eid_unseal = 0;
    initialize_enclave(ENCLAVE_NAME_UNSEAL, &eid_unseal);

    char n[15];
    
    printf("\nPlease input your first name: ");

    scanf("%s", n);
    char *name = n;
    strcat(name, ".txt");
    
    size_t fsize = get_file_size(name);

    //check errors in file
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << name << "\"" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        exit(1);
    }
    
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        exit(1);
    }
    if (read_file_to_buf(name, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << name << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        exit(1);
    }

    sgx_status_t retval;
    //send data to enclave to be unsealed
    unseal_data(eid_unseal, &retval, temp_buf, fsize);
    if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        exit(1);
    }

    printf("Enter your pin: ");
    int pinNum;
    scanf("%d", &pinNum);
    int identityStatus = 0;
    verifyIdentity(eid_unseal, &identityStatus, pinNum);
    if(identityStatus == 1){
        printf("Identity successfully verified!\n");
    }
    else{
        printf("Unable to verify identity. Exiting program now...\n");
        sgx_destroy_enclave(eid_unseal);
        exit(1);
    }
    
    int choice = 1;
    while(true){
        choice = transactionUI();
        if(choice == 0){
            break;
        }
        int transactionStatus = 0;
        processTransaction(eid_unseal, &transactionStatus, choice);
   
        if(transactionStatus == 1){
            printf("Action completed\n");
        }
        else{
            printf("Action could not be completed\n");
        }
    }
  
    sgx_destroy_enclave(eid_unseal);
    
}

//print string 
void printMem(uint8_t *str, uint32_t data_size){
    char *xd = (char*)str;
    cout << "MemInfo: " << xd << endl;
    (void)data_size;
}

void ocall_print_string(const char *str)
{
    cout << str << endl;

}

int getDeposit(){
    double u;
    printf("Enter amount to deposit: ");
    scanf("%lf", &u);
    return (int)(u * 100);  
}

int getWithdraw(){
    double u;
    printf("Enter amount to withdraw: ");
    scanf("%lf", &u);
    return (int)(u * 100); }

void printInfo(char *firstname, char *lastname, double balance){
    
    printf("\nACCOUNT INFO----------------\n");
    printf("Name: ");
    printf(" %s %s\n", firstname, lastname);
    printf("Account balance: %.2f\n", balance);
    printf("----------------------------\n");

}

//print error code
void abortPro(sgx_status_t ab){
    ret_error_support(ab);
}


























