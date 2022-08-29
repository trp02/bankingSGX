

//I ADD
#include "sgx_urts.h"
#include "Enclave_Unseal_u.h"
#include "ErrorSupport.h"
#include "App.h"
#define ENCLAVE_NAME_SEAL "libenclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "libenclave_unseal.signed.so"
#include <inttypes.h>
#include <stdio.h>
#include <map>
#include <sched.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <iostream>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include <string.h>
#include "EnclaveInitiator_u.h"
#define ENCLAVE_NAME_SEAL "libenclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "libenclave_unseal.signed.so"

//local attestation enclave
//#define ENCLAVE_INITIATOR_NAME "libenclave_initiator.signed.so"


void printMarshal(int *out_buff){
    printf("STRING: %d\n", *out_buff);
}
// FOREIGN FUNCTIONS END

int main(int argc, char* argv[])
{

 (void)argc, (void)argv;

      int user = 0;
    printf("Press 1 if you are a returning user and 2 if you are a new user: ");
    scanf("%d", &user);

    if(user == 1){
        returningUser();
    }
    else if(user == 2){
        getInitialInfo();
    }

    return 0;
}
