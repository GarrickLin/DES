#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include "des.h"

// Declare file handlers
static FILE *input_file, *output_file;

void mencrypting(unsigned char* des_key, unsigned char* file_data, unsigned long file_size){
	// Generate DES key set
	short int process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*)malloc(8 * sizeof(char));
	unsigned char* processed_block = (unsigned char*)malloc(8 * sizeof(char));
	key_set* key_sets = (key_set*)malloc(17 * sizeof(key_set));
	unsigned short int padding;
	process_mode = ENCRYPTION_MODE;
	generate_sub_keys(des_key, key_sets);
	// Get number of blocks in the file
	number_of_blocks = file_size / 8 + ((file_size % 8) ? 1 : 0);
	while (block_count++ < number_of_blocks){
		memcpy(data_block, file_data, 8);		
		if (block_count == number_of_blocks){
			padding = 8 - file_size % 8;
			if (padding < 8) { // Fill empty data block bytes with padding
				memset((data_block + 8 - padding), (unsigned char)padding, padding);
			}
			process_message(data_block, processed_block, key_sets, process_mode);
			memcpy(file_data, processed_block, 8);

			if (padding == 8){
				file_data += 8;
				memset(data_block, (unsigned char)padding, 8);
				process_message(data_block, processed_block, key_sets, process_mode);
				memcpy(file_data, processed_block, 8);
			}
		}
		else{
			process_message(data_block, processed_block, key_sets, process_mode);			
			memcpy(file_data, processed_block, 8);
		}
		memset(data_block, 0, 0);	
		file_data += 8;
	}
	// Free up memory
	free(data_block);
	free(processed_block);
	free(key_sets);
}

unsigned long mdecrypting(unsigned char* des_key, unsigned char* file_data, unsigned long file_size){
	// Generate DES key set
	short int process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*)malloc(8 * sizeof(char));
	unsigned char* processed_block = (unsigned char*)malloc(8 * sizeof(char));
	key_set* key_sets = (key_set*)malloc(17 * sizeof(key_set));
	unsigned short int padding;
	process_mode = DECRYPTION_MODE;
	generate_sub_keys(des_key, key_sets);
	// Get number of blocks in the file
	number_of_blocks = file_size / 8 + ((file_size % 8) ? 1 : 0);
	while (block_count++ < number_of_blocks) {
		memcpy(data_block, file_data, 8);
		if (block_count == number_of_blocks) {
			process_message(data_block, processed_block, key_sets, process_mode);
			padding = processed_block[7];
			if (padding < 8) {
				memcpy(file_data, processed_block, 8 - padding);
			}
		}
		else{
			process_message(data_block, processed_block, key_sets, process_mode);
			memcpy(file_data, processed_block, 8);
		}
		memset(data_block, 0, 8);
		file_data += 8;
	}

	// Free up memory
	free(data_block);
	free(processed_block);
	free(key_sets);
	return file_size - padding;
}

// Declare action parameters
#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"

int main(int argc, char* argv[]){
	if (argc < 2) {
		printf("You must provide at least 1 parameter, where you specify the action.");
		return 1;
	}
	if (argc != 4) {
		printf("Invalid # of parameters (%d) specified. Usage: run_des [-e|-d] input.file output.file", argc);
		return 1;
	}
	unsigned char des_key[8] = {1, 2, 3, 4, 5, 6, 7, 8};

	// Open input file
	input_file = fopen(argv[2], "rb");
	if (!input_file) {
		printf("Could not open input file to read data.");
		return 1;
	}

	// Open output file
	output_file = fopen(argv[3], "wb");
	if (!output_file) {
		printf("Could not open output file to write data.");
		return 1;
	}

	if (strcmp(argv[1], ACTION_ENCRYPT) == 0){		
		// read file data to memory
		fseek(input_file, 0L, SEEK_END);
		unsigned long file_size = ftell(input_file);
		fseek(input_file, 0L, SEEK_SET);
		unsigned long data_size = (file_size / 8 + 1) * 8;
		unsigned char* file_data = (unsigned char*)malloc(data_size * sizeof(char));
		unsigned long bytes_read = fread(file_data, 1, file_size, input_file);
		mencrypting(des_key, file_data, file_size);				
		fwrite(file_data, 1, data_size, output_file);
	}else if (strcmp(argv[1], ACTION_DECRYPT) == 0){
		// read file data to memory
		fseek(input_file, 0L, SEEK_END);
		unsigned long file_size = ftell(input_file);
		fseek(input_file, 0L, SEEK_SET);
		unsigned char* file_data = (unsigned char*)malloc(file_size * sizeof(char));
		unsigned long bytes_read = fread(file_data, 1, file_size, input_file);
		unsigned long write_szie = mdecrypting(des_key, file_data, file_size);
		fwrite(file_data, 1, write_szie, output_file);
	}else {
		printf("Invalid action: %s. First parameter must be [ -g | -e | -d ].", argv[1]);
		return 1;
	}

	fclose(input_file);
	fclose(output_file);
}