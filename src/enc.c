#include "cruxpass.h"
#include <sodium/crypto_pwhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void cleanup(FILE *source_file, FILE *target_file) {
  fclose(source_file);
  fclose(target_file);
}

static int generate_key_pass_hash(unsigned char *key, char *hashed_password,
                                  char *new_passd, unsigned char *salt,
                                  int tag) {

  switch (tag) {

  case 0:
    if (crypto_pwhash(key, sizeof(key), new_passd, strlen(new_passd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
      /* out of memory */
      fprintf(stderr, "Could not Generate New Password");
      return EXIT_FAILURE;
    }
    break;
  case 1:

    if (crypto_pwhash_str(hashed_password, new_passd, strlen(new_passd),
                          crypto_pwhash_OPSLIMIT_SENSITIVE,
                          crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
      /* out of memory */
      fprintf(stderr, "Fail to hash master password\n");
      return EXIT_FAILURE;
    }
    break;
  }
  return EXIT_SUCCESS;
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
  return EXIT_SUCCESS;
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

int authenticate(char *master_passd) {
  /* [TODO:]
   * hash the passd str
   * cmp it with the saved passd hash
   * if correct use the password to decrypt db
   */

  char hashed_password[crypto_pwhash_STRBYTES];
  int hash_read = 0;
  if (access("auth.db", F_OK) == 0) {
    FILE *master_fp;
    if ((master_fp = fopen("auth.db", "rb")) != NULL) {
      hash_read = fread(hashed_password, sizeof(hashed_password), 1, master_fp);
      if (!hash_read) {
        fprintf(stderr, "No master password found\n");
        return EXIT_FAILURE;
      }
    }
  } else {
    perror("Fail To Authencate\n");
    return EXIT_FAILURE;
  }

  if (crypto_pwhash_str_verify(hashed_password, master_passd,
                               strlen(master_passd)) != 0) {
    /* wrong password */
    fprintf(stderr, "Wrong Password...\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int create_new_master_passd(char *master_passd) {
  char hashed_password[crypto_pwhash_STRBYTES + 1];
  char *new_passd;
  char *temp_passd;
  hashed_pass_t *old_hashed_password = NULL;
  FILE *master_fp = NULL;

  if (authenticate(master_passd) != 0) {
    return EXIT_FAILURE;
  }

  new_passd = getpass("New Password: ");
  if (strlen(new_passd) > PASSLENGTH) {
    fprintf(stderr, "Password Too Long\n");
    return EXIT_FAILURE;
  }

  temp_passd = getpass("Confirm New Password: ");
  if (strncmp(new_passd, temp_passd, PASSLENGTH) == 0 &&
      strlen(temp_passd) <= PASSLENGTH) {

    char passstr[crypto_pwhash_STRBYTES + crypto_pwhash_SALTBYTES + 2];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char old_salt[crypto_pwhash_SALTBYTES];
    unsigned char key[KEY_LEN];

    randombytes_buf(salt, sizeof salt);

    if ((master_fp = fopen("auth.db", "rb+")) == NULL) {
      perror("Fail To open AUTH_DB");
      return EXIT_FAILURE;
    }

    old_hashed_password = malloc(sizeof(hashed_pass_t));
    if (old_hashed_password == NULL) {
      fprintf(stderr, "Memory Allocation Fail\n");
      return EXIT_FAILURE;
    }

    fread(old_hashed_password, sizeof(hashed_pass_t), 1, master_fp);
    generate_key_pass_hash(NULL, hashed_password, new_passd, salt, 1);
    generate_key_pass_hash(key, NULL, master_passd, old_hashed_password->salt,
                           0);

    rewind(master_fp);
    sprintf(passstr, "%s%s", hashed_password, salt);
    fputs(passstr, master_fp);
    fclose(master_fp);

    if (decrypt("tmp_password.db", "password.db", key) != 0) {
      fprintf(stderr, "Fail to decrypt PASSWORD_DB\n");
      return EXIT_FAILURE;
    }

    generate_key_pass_hash(key, NULL, new_passd, salt, 0);
    remove("password.db");
    encrypt("password.db", "tmp_password", key);
    remove("tmp_password");
  } else {
    fprintf(stderr, "Passwords do not march\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

void __initcrux() {
  //[TODO]: createa getpass function
  if (access("auth.db", F_OK) != 0) {
    int opt = -1;
    char *new_passd = NULL;
    char *temp_passd = NULL;
    hashed_pass_t *pass_hashWsalt;

    if (access("password.db", F_OK) == 0) {
      fprintf(stdout, "There is a PASSWORD_DB found...\n");
      fprintf(stdout, "Would you like to create a backup [Y/N]\n");
      do {
        opt = getchar();

      } while (opt != 'Y' || opt != 'N');
    }
    if (opt == 'Y')
      rename("password.db", "password_backup.db");
    else
      remove("password.db");

    FILE *master_fp;

    new_passd = calloc(PASSLENGTH, sizeof(char));
    temp_passd = calloc(PASSLENGTH, sizeof(char));

    if (new_passd == NULL || temp_passd == NULL) {
      perror("Calloc");
      return;
    }

    fprintf(stdout, "Create a new Master Password\n");
    new_passd = getpass("New Password: ");
    if (strlen(new_passd) > PASSLENGTH) {
      fprintf(stderr, "Password Too Long\n");
      return;
    }

    temp_passd = getpass("Confirm New Password: ");

    if (strcmp(new_passd, temp_passd) != 0) {
      fprintf(stderr, "Password Do Not Match\n");
      goto free_mm;
    }

    randombytes_buf(pass_hashWsalt->salt, crypto_pwhash_SALTBYTES);

    if ((master_fp = fopen("auth.db", "wb")) == NULL) {
      perror("Fail To open AUTH_DB");
      goto free_mm;
    }

    generate_key_pass_hash(NULL, pass_hashWsalt->password_hash, new_passd, NULL,
                           1);
    if (sprintf(passstr, "%s%s", hashed_password, salt) < 0) {
      fprintf(stderr, "sprintf Failed\n");
      fclose(master_fp);
      return;
    }

    fputs(passstr, master_fp);
    fclose(master_fp);

  free_mm:
    free(passstr);
    free(new_passd);
    free(salt);
    free(hashed_password);
    return;
  }
}
