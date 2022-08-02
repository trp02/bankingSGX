/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

//I ADD
#include "sgx_urts.h"
#include <execinfo.h>
#include "Enclave_Unseal_u.h"

#include "ErrorSupport.h"

#include "App.h"
#define ENCLAVE_NAME_SEAL "libenclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "libenclave_unseal.signed.so"
#include <inttypes.h>
//


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
//#define ENCLAVE_INITIATOR_NAME "libenclave_seal.signed.so"
// FOREIGN FUNCTIONS START


void printMarshal(int *out_buff){
    printf("STRING: %d\n", *out_buff);
}
// FOREIGN FUNCTIONS END

int main(int argc, char* argv[])
{    
    void *ar[15];

    char**strng; 
    int numTrace = backtrace(ar, 15);
    strng = backtrace_symbols(ar, numTrace);
    for(int i = 0; i < numTrace; i++){
        printf("MAIN FUNTION %s\n", strng[i]);
    }
    
 
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
   
    


/* 
      // Enclave_Seal: seal the secret and save the data blob to a file
    if (seal_and_save_data() == false)
    {
        std::cout << "Failed to seal the secret and save it to a file." << std::endl;
        return -1;
    }

    // Enclave_Unseal: read the data blob from the file and unseal it.
    if (read_and_unseal_data() == false)
    {
        std::cout << "Failed to unseal the data blob." << std::endl;
        return -1;
    }

  
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

    sgx_destroy_enclave(initiator_enclave_id);
*/
    return 0;
} 
