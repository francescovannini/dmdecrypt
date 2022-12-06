// Copyright (C) 2022 Francesco Vannini
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#define _FILE_OFFSET_BITS 64

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <getopt.h>
#include <libgen.h>
#include <unistd.h>
#include <stdint.h>

#define BUFSIZE 256
#define SECSIZE 512
#define MAXKEYSIZE 32
typedef unsigned char sector_t[SECSIZE];

_Static_assert(AES_BLOCK_SIZE == 16, "AES_BLOCK_SIZE is expected to be 16 bytes");

bool ProcessSector(uint64_t sec_num, unsigned char *in_data, unsigned char *key, unsigned short key_len,
                   unsigned char *key_hash, unsigned char *out_data, bool encrypt_mode) {

    // Encrypts the sector number using the hashed key and zeros as IV
    // https://en.wikipedia.org/wiki/Disk_encryption_theory#Encrypted_salt-sector_initialization_vector_(ESSIV)

    EVP_CIPHER_CTX *essiv_ctx;
    if (!(essiv_ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherInit(essiv_ctx, EVP_aes_256_cbc(), key_hash, NULL, true)) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    int out_len;
    static unsigned char essiv[AES_BLOCK_SIZE];
    static unsigned char sec_buf[AES_BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(&sec_buf[0], &sec_num, sizeof(sec_num));
    if (!EVP_CipherUpdate(essiv_ctx, &essiv[0], &out_len, &sec_buf[0], AES_BLOCK_SIZE)) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    EVP_CIPHER_CTX_free(essiv_ctx);

    if (out_len != AES_BLOCK_SIZE) {
        return false;
    }

    // En/Decrypts the sector data using the key and the ESSIV calculated above
    EVP_CIPHER_CTX *sec_ctx;
    if (!(sec_ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Dynamically select the AES cipher based on key length
    int init_res;
    switch (key_len) {
        case 16:
            init_res = EVP_CipherInit(sec_ctx, EVP_aes_128_cbc(), key, &essiv[0], encrypt_mode);
            break;
        case 24:
            init_res = EVP_CipherInit(sec_ctx, EVP_aes_192_cbc(), key, &essiv[0], encrypt_mode);
            break;
        case 32:
            init_res = EVP_CipherInit(sec_ctx, EVP_aes_256_cbc(), key, &essiv[0], encrypt_mode);
            break;
        default:
            return false;
    }

    if (!init_res) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CIPHER_CTX_set_padding(sec_ctx, 0)) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherUpdate(sec_ctx, out_data, &out_len, in_data, SECSIZE)) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (out_len != SECSIZE) {
        return false;
    }

    EVP_CIPHER_CTX_free(sec_ctx);

    return true;
}


void ShowHelp(char *command, int exitcode) {
    fprintf(stderr, "De(En)crypts a dmcrypt-style aes-cbc-essiv:sha256 disk volume\n");
    fprintf(stderr, "Usage: %s [-e] [-y] [-q] input output key\n", basename(command));
    fprintf(stderr, "  -e     Encrypt; if not specified, default is to decrypt.\n");
    fprintf(stderr, "  -y     Overwrite output file if it exists.\n");
    fprintf(stderr, "  -q     Quiet output. Only print errors.\n");
    fprintf(stderr, "  input  Input disk volume. Size in bytes must be a multiple of 512.\n");
    fprintf(stderr, "  output Output disk volume.\n");
    fprintf(stderr, "  key    Key file. Must be either 16, 24 or 32 bytes long.\n");
    exit(exitcode);
}

int main(int argc, char *argv[]) {
    int opt;
    bool encrypt_mode = false;
    bool quiet = false;
    bool overwrite_existing = false;

    while ((opt = getopt(argc, argv, ":eqy")) != -1) {
        switch (opt) {
            case 'e':
                encrypt_mode = true;
                break;

            case 'q':
                quiet = true;
                break;

            case 'y':
                overwrite_existing = true;
                break;

            case '?':
                fprintf(stderr, "Unknown option -%c, ignored.\n", optopt);
                break;

            default:
                ShowHelp(argv[0], EXIT_FAILURE);
        }
    }

    // Not enough params
    if (optind > argc - 3) {
        ShowHelp(argv[0], EXIT_FAILURE);
    }

    char *in_filename = argv[optind];
    char *out_filename = argv[optind + 1];
    char *key_filename = argv[optind + 2];

    if (!overwrite_existing) {
        if (access(out_filename, F_OK) == 0) {
            fprintf(stderr, "Output file %s exists but can't overwrite it, exiting.\n", out_filename);
            exit(0);
        }
    }

    FILE *key_file;
    if (!(key_file = fopen(key_filename, "rb"))) {
        fprintf(stderr, "Error opening key file: %s\n", strerror(errno));
        exit(1);
    }

    unsigned short key_size;
    unsigned char key[MAXKEYSIZE];
    key_size = fread(key, sizeof(unsigned char), MAXKEYSIZE, key_file);
    if (ferror(key_file) != 0) {
        fprintf(stderr, "Error reading key file: %s\n", strerror(errno));
        fclose(key_file);
        exit(1);
    }
    fclose(key_file);

    if ((key_size != 16) && (key_size != 24) && (key_size != 32)) {
        fprintf(stderr, "Key length is (%d) bytes but only 16, 24 or 32 bytes keys are supported.\n", key_size);
        exit(1);
    }

    // Open input
    FILE *in_file;
    if (!(in_file = fopen(in_filename, "rb"))) {
        fprintf(stderr, "Error opening input file: %s\n", strerror(errno));
        exit(1);
    }

    // Input file is supposed to be made of sectors
    fseek(in_file, 0L, SEEK_END);
    uint64_t in_file_len = ftello(in_file);
    if ((in_file_len % SECSIZE) != 0) {
        fprintf(stderr, "Error: input file length must be a multiple of 512\n");
        fclose(in_file);
        exit(1);
    }
    uint64_t sec_total = in_file_len / 512;
    fseek(in_file, 0L, SEEK_SET);

    FILE *out_file;
    if (!(out_file = fopen(out_filename, "wb"))) {
        fprintf(stderr, "Error opening output file: %s\n", strerror(errno));
        exit(1);
    }

    if (!quiet) {
        if (encrypt_mode) {
            fprintf(stdout, "En");
        } else {
            fprintf(stdout, "De");
        }
        fprintf(stdout, "coding using AES-%d-CBC (based on key length)\n", key_size * 8);
    }

    // Get a SHA256 hash of the key
    unsigned char key_hash[SHA256_DIGEST_LENGTH];
    SHA256(key, key_size, &(key_hash[0]));

    sector_t in_buf[BUFSIZE], out_buf[BUFSIZE];
    uint64_t sec_idx = 0;
    time_t raw_time;
    unsigned long start_time = time(&raw_time);
    unsigned long check_time = start_time + 5;
    unsigned long now;
    while (!feof(in_file)) {
        unsigned int in_buf_len = fread(&in_buf, sizeof(sector_t), BUFSIZE, in_file);
        for (unsigned int s = 0; s < in_buf_len; s++) {
            if (!ProcessSector(sec_idx + s, in_buf[s], key, key_size, key_hash, out_buf[s], encrypt_mode)) {
                fprintf(stderr, "Error encoding/decoding sector: %lu. Invalid key or input file corrupted.\n",
                        sec_idx + s);
                fclose(in_file);
                fclose(out_file);
                exit(1);
            }
        }

        if (fwrite(&out_buf[0], sizeof(sector_t), in_buf_len, out_file) < in_buf_len) {
            fprintf(stderr, "Error writing output file: %s\n", strerror(errno));
            fclose(in_file);
            fclose(out_file);
            exit(1);
        }

        sec_idx += in_buf_len;
        if (!quiet) {
            now = time(&raw_time);
            if (now > check_time) {
                check_time = now + 3;
                fprintf(stdout, "Processed %" PRId64 " sectors out of %" PRId64 " (%.0f%%). Speed: %.2f MB/s\n",
                        sec_idx, sec_total, 100.0f / (double) sec_total * (double) sec_idx,
                        (double) (sec_idx * 512) / (double) (now - start_time) / 1048576.0f);
            }
        }
    }
    now = time(&raw_time);

    fclose(in_file);
    fclose(out_file);
    if (!quiet) {
        fprintf(stdout, "Processed %lu sector at  %.2f MB/s\n", sec_idx,
                (double) (sec_idx * 512) / (double) (now - start_time) / 1048576.0f);
    }

    exit(0);
}
