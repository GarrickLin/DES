#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include "des.h"

// Declare file handlers
static FILE *input_file, *output_file;

void encrypting(unsigned char* des_key){
	// Generate DES key set
	short int bytes_written, process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*)malloc(8 * sizeof(char));
	unsigned char* processed_block = (unsigned char*)malloc(8 * sizeof(char));
	key_set* key_sets = (key_set*)malloc(17 * sizeof(key_set));
	unsigned short int padding;
	unsigned long file_size;
	process_mode = ENCRYPTION_MODE;
	generate_sub_keys(des_key, key_sets);
	// Get number of blocks in the file
	fseek(input_file, 0L, SEEK_END);
	file_size = ftell(input_file);
	fseek(input_file, 0L, SEEK_SET);
	number_of_blocks = file_size / 8 + ((file_size % 8) ? 1 : 0);

	while (fread(data_block, 1, 8, input_file)) {
		block_count++;
		if (block_count == number_of_blocks) {
			padding = 8 - file_size % 8;
			if (padding < 8) { // Fill empty data block bytes with padding
				memset((data_block + 8 - padding), (unsigned char)padding, padding);
			}

			process_message(data_block, processed_block, key_sets, process_mode);
			bytes_written = fwrite(processed_block, 1, 8, output_file);

			if (padding == 8) { // Write an extra block for padding
				memset(data_block, (unsigned char)padding, 8);
				process_message(data_block, processed_block, key_sets, process_mode);
				bytes_written = fwrite(processed_block, 1, 8, output_file);
			}
		}
		else{
			process_message(data_block, processed_block, key_sets, process_mode);
			bytes_written = fwrite(processed_block, 1, 8, output_file);
		}
		memset(data_block, 0, 8);
	}

	// Free up memory
	free(data_block);
	free(processed_block);
	free(key_sets);
}

void decrypting(unsigned char* des_key){
	// Generate DES key set
	short int bytes_written, process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*)malloc(8 * sizeof(char));
	unsigned char* processed_block = (unsigned char*)malloc(8 * sizeof(char));
	key_set* key_sets = (key_set*)malloc(17 * sizeof(key_set));
	unsigned short int padding;
	unsigned long file_size;
	process_mode = DECRYPTION_MODE;
	generate_sub_keys(des_key, key_sets);
	// Get number of blocks in the file
	fseek(input_file, 0L, SEEK_END);
	file_size = ftell(input_file);
	fseek(input_file, 0L, SEEK_SET);
	number_of_blocks = file_size / 8 + ((file_size % 8) ? 1 : 0);

	while (fread(data_block, 1, 8, input_file)) {
		block_count++;
		if (block_count == number_of_blocks) {
			process_message(data_block, processed_block, key_sets, process_mode);
			padding = processed_block[7];

			if (padding < 8) {
				bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
			}
		}
		else{
			process_message(data_block, processed_block, key_sets, process_mode);
			bytes_written = fwrite(processed_block, 1, 8, output_file);
		}
		memset(data_block, 0, 8);
	}

	// Free up memory
	free(data_block);
	free(processed_block);
	free(key_sets);
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
	unsigned char des_key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

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
		encrypting(des_key);
	}
	else if (strcmp(argv[1], ACTION_DECRYPT) == 0){
		decrypting(des_key);
	}
	else {
		printf("Invalid action: %s. First parameter must be [ -g | -e | -d ].", argv[1]);
		return 1;
	}

	fclose(input_file);
	fclose(output_file);
}