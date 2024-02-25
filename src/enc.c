#include "cruxpass.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int create_newPASS() {
  char hashed_password[crypto_pwhash_STRBYTES];
  FILE *master_fp;

  char new_pass[PASSLENGTH];
  if (access("autho.db", F_OK) == 0) {
    int hash_read = 0;

    if ((master_fp = fopen("autho.db", "rb")) != NULL) {
      hash_read = fread(hashed_password, sizeof(hashed_password), 1, master_fp);
      if (!hash_read) {
        fprintf(stderr, "No master password found\n");
      } else {

        char *old_pass = getpass("Enter Old Password: ");
        if (strlen(old_pass) > PASSLENGTH) {
          fprintf(stderr, "INVALID PASSWORD: Password Too Long\n");
          fclose(master_fp);
          return EXIT_FAILURE;
        }

        if (crypto_pwhash_str_verify(hashed_password, old_pass,
                                     strlen(old_pass)) != 0) {
          fprintf(stderr, "INVALID PASSWORD");
          fclose(master_fp);
          return EXIT_FAILURE;
        }
      }
    }
    fclose(master_fp);
  }
}

int authentication(void *master_passd) {
  /* [TODO:]
   * hash the passd str
   * cmp it with the saved passd hash
   * if correct use the password to decrypt db
   */

  char hashed_password[crypto_pwhash_STRBYTES];
  int hash_read = 0;
  if (access("autho.db", F_OK) == 0) {
    FILE *master_fp;
    if ((master_fp = fopen("autho.db", "rb")) != NULL) {
      hash_read = fread(hashed_password, sizeof(hashed_password), 1, master_fp);
      if (!hash_read) {
        fprintf(stderr, "No master password found\n");
      }
    }
  } else {
    perror("Fail To Authencate\n");
    return EXIT_FAILURE;
  }

  // if (crypto_pwhash_str(hashed_password, master_passd,
  // strlen(master_passd),
  //                       crypto_pwhash_OPSLIMIT_SENSITIVE,
  //                       crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
  //   /* out of memory */
  //   fprintf(stderr, "Fail to hash master password\n");
  //   return EXIT_FAILURE;
  // }
  //
  if (crypto_pwhash_str_verify(hashed_password, master_passd,
                               strlen(master_passd)) != 0) {
    /* wrong password */
    fprintf(stderr, "Wrong Password...\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

#define CHUNK_SIZE 4096

static void cleanup(FILE *source_file, FILE *target_file) {
  fclose(source_file);
  fclose(target_file);
}

static int encrypt(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
  unsigned char buf_in[CHUNK_SIZE];

  unsigned char
      buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;

  FILE *fp_target, *fp_source;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag;

  fp_source = fopen(source_file, "rb");
  fp_target = fopen(target_file, "wb");
  crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
  fwrite(header, 1, sizeof header, fp_target);
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_source);
    eof = feof(fp_source);
    tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
    crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in,
                                               rlen, NULL, 0, tag);
    fwrite(buf_out, 1, (size_t)out_len, fp_target);
  } while (!eof);
  cleanup(fp_source, fp_target);
  return 0;
}

static int decrypt(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {

  unsigned char
      buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

  unsigned char buf_out[CHUNK_SIZE];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;

  FILE *fp_target, *fp_source;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  int ret = -1;
  unsigned char tag;

  fp_source = fopen(source_file, "rb");
  fp_target = fopen(target_file, "wb");
  fread(header, 1, sizeof header, fp_source);
  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
    cleanup(fp_source, fp_target);
    return EXIT_FAILURE;
  }
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_source);
    eof = feof(fp_source);
    if (crypto_secretstream_xchacha20poly1305_pull(
            &st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {
      cleanup(fp_source, fp_target);
      return EXIT_FAILURE; /* corrupted chunk */
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      if (!eof) {
        cleanup(fp_source, fp_target);
        return EXIT_FAILURE; /* end of stream reached before the end of the
                              * file
                              */
      }
    } else { /* not the final chunk yet */
      if (eof) {

        cleanup(fp_source, fp_target);
        return EXIT_FAILURE;
        /* end of file reached before the end of the stream */
      }
    }
    fwrite(buf_out, 1, (size_t)out_len, fp_target);
  } while (!eof);

  return EXIT_SUCCESS;
}
