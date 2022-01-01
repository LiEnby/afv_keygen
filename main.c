#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "crypto/aes_cbc.h"
#include "crypto/aes.h"
#include "crypto/aes_cmac.h"

uint8_t devkit_act_key[0x20] = {0x84, 0x6D, 0x2D, 0xFD, 0x77, 0xD3, 0xC2, 0xE5, 0xF0, 0xE1, 0x7E, 0xB1, 0x8C, 0xC7, 0x86, 0x92, 0x8B, 0x88, 0x1E, 0x2E, 0x17, 0xAE, 0x0C, 0xD8, 0xFD, 0xE8, 0x88, 0x09, 0xD0, 0xD0, 0x33, 0xC5};

uint8_t devkit_act_iv[0x10]  = {0xC8, 0xA0, 0x40, 0x66, 0x2B, 0x10, 0xA1, 0x98, 0x6A, 0x18, 0x94, 0xE9, 0x4F, 0xBE, 0xFC, 0xF0};

#define CHECKSUM_SIZE 4
#define PSID_CHECKSUM_OFFSET (psid + (size - CHECKSUM_SIZE))
unsigned char* hex2bin(const char* hexstr, size_t* size)
{
    size_t hexstrLen = strlen(hexstr);
    size_t bytesLen = hexstrLen / 2;

    unsigned char* bytes = (unsigned char*) malloc(bytesLen);

    int count = 0;
    const char* pos = hexstr;

    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    if( size != NULL )
        *size = bytesLen;

    return bytes;
}

void bin2hex(char* src, char* dst, int size){
	char *ptr = &dst[0];
	for(int i = 0; i < size; i++){
		ptr += sprintf(ptr, "%02X", (uint8_t)src[i]);
	}
}


void calc_act_checksum(uint8_t *psid)
{
	uint8_t checksum[CHECKSUM_SIZE];
	memset(checksum, 0x00, CHECKSUM_SIZE);
	
	for (int pi = 0; pi < 0x10; pi += 0x4)
	{	
		checksum[0] += psid[pi];
		for(int ci = 1; ci != 4; ++ci)
		{
			checksum[ci] += psid[pi + ci];	
		}
		
	}
	
	memcpy(psid + 0x10, checksum, CHECKSUM_SIZE);
}

// Checks if the user entered the "Show activation key" correctly
// (OpenPSID)                         (checksum)
// Returns: psid
uint8_t* verify_activation_key(uint8_t* activation_key){
	uint8_t work[1028];
	uint8_t entered_checksum[CHECKSUM_SIZE];
	uint8_t expected_checksum[CHECKSUM_SIZE];
	uint8_t* psid = NULL;
	
	memset(work, 0x00, sizeof(work));
	
	// verify activation key is exactly 44 characters long
	size_t act_len = strlen(activation_key);
	if(act_len != 44)
		goto validation_fail;
	
	// Verify '-' at every 8 positions.
	for(int i = 8; i < act_len; i+= 9){
		if(activation_key[i] != '-')
			goto validation_fail;
	}
	
	// Make a copy of the string without '-'
	int copy_loc = 0;
	for(int i = 0; i < act_len; i++){
		if(activation_key[i] != '-'){
			work[copy_loc++] = activation_key[i];
		}
	}
	
	size_t size;
	psid = hex2bin(work, &size);
	
	// If hex data is larger than 20 bytes, FAIL
	if(size != 20)
		goto validation_fail;
	
	// copy checksum part:
	memcpy(entered_checksum, PSID_CHECKSUM_OFFSET, CHECKSUM_SIZE);
	
	// zero out original checksum
	memset(PSID_CHECKSUM_OFFSET, 0x00, CHECKSUM_SIZE);
	
	// generate expected checksum, leaving psid
	calc_act_checksum(psid);
	// copy expected checksum to expected_checksum buffer
	memcpy(expected_checksum, PSID_CHECKSUM_OFFSET, CHECKSUM_SIZE);
	
	
	// Finally compare expected checksum to the entered checksum-
	if(memcmp(entered_checksum, expected_checksum, CHECKSUM_SIZE) != 0)
		goto validation_fail;
	
	// zero out original checksum, leaving psid
	memset(PSID_CHECKSUM_OFFSET, 0x00, CHECKSUM_SIZE);
	
	return psid;
	
	validation_fail:
	if(psid != NULL)
		free(psid);
	return NULL;
}


typedef struct {
	uint8_t magic[4];
	uint32_t version;
	uint32_t issue_number;
	uint32_t start_time;
	uint32_t end_time;
	uint8_t psid[0x10];
	uint8_t reserved[0xC];
	uint8_t signature[0x10];
	
} ActivationBuffer;


int main(int argc, char *argv[]){	
	if(argc < 4){
		printf("Notice: This only works on firmware 2.10 and below!\n");
		printf("BACKUP YOUR ORIGINAL ACT/ACTSIG BEFORE USING THIS!!!\n");
		
		printf("Usage: <activation_key> <issue_number> <days> [vita_activation.afv]\n");
		printf("       activation_key: the activation key in settings\n");
		printf("       issue_number: total number of activations + 1\n");
		printf("       days: how many days to activate for?\n");
		goto error;
	}
	char* activation_key = argv[1];
	uint32_t issue_number = atoi(argv[2]);	
	uint32_t days = atoi(argv[3]);
	char* output_name;
	if(argc <= 4)
		output_name = argv[4];
	else
		output_name = "vita_activation.afv";

	printf("Validating activation key...");
	uint8_t* psid = verify_activation_key(activation_key);
	if(psid != NULL){
		printf("OK\n");
	}
	else{
		printf("FAIL\n");
		goto error;
	}
	
	printf("Generating activation token...");
	
	uint32_t valid_from = (uint32_t)time(NULL);
	uint32_t valid_until = (uint32_t)time(NULL) + (days*86400);
	
	ActivationBuffer activation_buffer;
	memset(&activation_buffer, 0x0, sizeof(ActivationBuffer));	
	
	strncpy(activation_buffer.magic, "act", 0x4);
	activation_buffer.version = 1;
	activation_buffer.issue_number = issue_number;
	activation_buffer.start_time = valid_from;
	activation_buffer.end_time = valid_until;
	memcpy(activation_buffer.psid, psid, 0x10);
	
	
	printf("OK!\n");
	
	printf("Signing...");
	// sign it
	uint8_t cmac[0x10];
	aes_cmac((uint8_t*)&activation_buffer, sizeof(ActivationBuffer), devkit_act_key, cmac);
	memcpy(&activation_buffer.signature, cmac, 0x10);
	printf("OK!\n");
	
	printf("Encrypting...");
	// encrypt it
	uint8_t ciphertext_buffer[sizeof(ActivationBuffer)];
	AES_CBC_encrypt((uint8_t*)&activation_buffer, ciphertext_buffer, sizeof(ActivationBuffer), devkit_act_key, 32, devkit_act_iv);
	printf("OK!\n");
	
			
	printf("Generating AFV....\n\n\n");
	
	uint8_t psid_hex[0x500];
	uint8_t ciphertext_buffer_hex[0x500];

	memset(psid_hex, 0x00, sizeof(psid_hex));
	memset(ciphertext_buffer_hex, 0x00, sizeof(ciphertext_buffer_hex));
	
	bin2hex(psid, psid_hex, 0x10);
	bin2hex(ciphertext_buffer, ciphertext_buffer_hex, sizeof(ActivationBuffer));
	uint8_t tokens[0x80000];
	snprintf(tokens, 0x80000-1, "%s, %u, %u,         %u, %s\n",psid_hex, valid_from, valid_until, issue_number, ciphertext_buffer_hex);

	FILE* afv = fopen(output_name, "wb");
	
	fprintf(afv, "# VITA/ActivationCode\n");
	printf("# VITA/ActivationCode\n");
	fprintf(afv, "# format_version=1\n");
	printf("# format_version=1\n");
	fprintf(afv, "# code_num=1\n");
	printf("# code_num=1\n");
	
	fprintf(afv, "# code_size=%u\n", (uint32_t)strlen(tokens));
	printf("# code_size=%u\n", (uint32_t)strlen(tokens));
	
	fprintf(afv, "%s", tokens);
	printf("%s", tokens);
	
	free(psid);
	printf("\n\nBlessed Be!~\n");
	error:
	return 1;

}
