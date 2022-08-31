
#ifndef _APP_H
#define _APP_H

#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "sgx_urts.h"
#include "Enclave_Seal_u.h"
#include "Enclave_Unseal_u.h"
#include <string.h>
#include "ErrorSupport.h"
#define ENCLAVE_NAME_SEAL "libenclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "libenclave_unseal.signed.so"
//#define SEALED_DATA_FILE "sealed_data_blob.txt"




 size_t get_file_size(const char *filename);
 bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize);
 bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset);

 sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid);
 bool seal_and_save_data();
 bool read_and_unseal_data();
 void getInitialInfo();
 void returningUser();

#endif
