
#include "sgx_urts.h"
#include "Enclave_Unseal_u.h"
#include "ErrorSupport.h"
#include "App.h"

#include <execinfo.h>
#include <inttypes.h>
#include <iostream>
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
#define ENCLAVE_INITIATOR_NAME "libenclave_initiator.signed.so"
using namespace std;


void printMarshal(int *out_buff){

    void *aa[15];
    char**ss; 
    int nn = backtrace(aa, 15);
    ss = backtrace_symbols(aa, nn);
    for(int i = 0; i < nn; i++){
        printf("PRINT MARSHAL OCALL %s\n", ss[i]);

    }
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


//LOCAL ATTESTATION EXAMPLE
/*
    int update = 0;
    uint32_t ret_status;
    sgx_status_t status;
    sgx_launch_token_t token = {0};
    sgx_enclave_id_t initiator_enclave_id = 0;



    // create ECDH initiator enclave
    status = sgx_create_enclave(ENCLAVE_INITIATOR_NAME, SGX_DEBUG_FLAG, &token, &update, &initiator_enclave_id, NULL);
    if (status != SGX_SUCCESS) {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_INITIATOR_NAME, status);
        return -1;
    }
    printf("succeed to load initiator enclave %s\n", ENCLAVE_INITIATOR_NAME);

    // create ECDH session using initiator enclave, it would create ECDH session with responder enclave running in another process
    status = test_create_session(initiator_enclave_id, &ret_status);
    

    
    
    if (status != SGX_SUCCESS || ret_status != 0) {
       // printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        printf("failed to establish connection to responder endclave: error code 0x%x \n", ret_status);
        printf("exiting program now..\n");
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }
    printf("succeed to establish secure channel.\n");

    // Test message exchange between initiator enclave and responder enclave running in another process
    status = test_message_exchange(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
       // printf("test_message_exchange Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        printf("failed to exchange test message: error code 0x%x \n", ret_status);
        printf("exiting program now..\n");
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }
    printf("Succeed to exchange secure message test...\n");
    
    // close ECDH session
    status = test_close_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }
    
    printf("Succeed to close Session...\n");

    sgx_destroy_enclave(initiator_enclave_id);*/


    return 0;
} 
