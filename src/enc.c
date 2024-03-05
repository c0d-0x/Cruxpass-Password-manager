#include "cruxpass.h"
#include <ctype.h>
#include <sodium/crypto_pwhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void cleanup(FILE *source_file, FILE *target_file) {
  fclose(source_file);
  fclose(target_file);
}

char *getpass_custom(void) {
  char *temp_passd = calloc(PASSLENGTH, sizeof(char));
  if (temp_passd == NULL) {
    perror("calloc");
    return NULL;
  }
  printf("Master Password: ");
  fgets(temp_passd, PASSLENGTH, stdin);
  temp_passd[strlen(temp_passd) - 1] = '\0';
  if (strlen(temp_passd) < 8) {
    fprintf(stdin, "Invalid Password: password too short\n");
    return NULL;
  }
  return temp_passd;
}

int generate_key_pass_hash(unsigned char *key, char *hashed_password,
                           char *new_passd, unsigned char *salt, int tag) {

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

int encrypt(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {

  unsigned char *buf_in = malloc(sizeof(char) * CHUNK_SIZE);

  unsigned char *buf_out =
      malloc(sizeof(char) *
             (CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES));

  unsigned char *header = malloc(
      sizeof(char) * (crypto_secretstream_xchacha20poly1305_HEADERBYTES));

  if (buf_in == NULL || buf_out == NULL || header == NULL) {
    perror("Memory Allocation Fail");
    return EXIT_FAILURE;
  }

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
  fclose(fp_target);
  fclose(fp_source);
  free(buf_out);
  free(buf_in);
  free(header);
  return EXIT_SUCCESS;
}

int decrypt(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {

  unsigned char *buf_in =
      malloc(sizeof(char) *
             (CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES));

  unsigned char *buf_out = malloc(sizeof(char) * CHUNK_SIZE);
  unsigned char *header =
      malloc(sizeof(char) * crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  crypto_secretstream_xchacha20poly1305_state st;

  if (buf_in == NULL || buf_out == NULL || header == NULL) {
    perror("Memory Allocation Fail");
    return EXIT_FAILURE;
  }

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

  fclose(fp_target);
  fclose(fp_source);
  free(buf_out);
  free(buf_in);
  free(header);
  return EXIT_SUCCESS;
}

hashed_pass_t *authenticate(char *master_passd) {
  /* [TODO:]
   * hash the passd str
   * cmp it with the saved passd hash
   * if correct use the password to decrypt db
   */

  hashed_pass_t *hashed_password = calloc(1, sizeof(hashed_pass_t));
  int hash_read = 0;
  if (access("auth.db", F_OK) == 0) {
    FILE *master_fp;
    if ((master_fp = fopen("auth.db", "rb")) != NULL) {
      hash_read = fread(hashed_password, sizeof(hashed_pass_t), 1, master_fp);
      if (!hash_read) {
        fprintf(stderr, "No master password found\n");
        return NULL;
      }
    }
  } else {
    perror("Fail To Authencate\n");
    return NULL;
  }

  if (crypto_pwhash_str_verify(hashed_password->hash, master_passd,
                               strlen(master_passd)) != 0) {
    /* wrong password */
    fprintf(stderr, "Wrong Password...\n");
    return NULL;
  }
  return hashed_password;
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
static void backup_choice(void) {
  char opt;

  do {
    printf("Do you want to rename or delete the password database (R/D)? ");
    fflush(stdout);              /* Flush standard output before reading input*/
    opt = tolower(fgetc(stdin)); /* Read character and convert to lowercase */

    if (opt == 'r' || opt == 'd') {
      break;
    } else {
      printf("Invalid input. Please enter 'Y' or 'N'.\n");
    }
  } while (1);

  if (opt == 'r') {
    if (rename("password.db", "password_backup.db") != 0) {
      perror("Error renaming file");
      return;
    }
    printf("Password database renamed successfully.\n");
  } else {
    if (remove("password.db") != 0) {
      perror("Error deleting file");
      return;
    }
    printf("Password database deleted successfully.\n");
  }
}

void __initcrux() {
  // [TODO]: createa getpass function
  if (access("auth.db", F_OK) != 0) {
    char *new_passd = NULL;
    char *temp_passd = NULL;
    hashed_pass_t *pass_hashWsalt = NULL;

    if (access("password.db", F_OK) == 0) {
      fprintf(stdout, "There is a PASSWORD_DB found...\n");
      backup_choice();
    }
    FILE *master_fp;

    new_passd = calloc(PASSLENGTH, sizeof(char));
    temp_passd = calloc(PASSLENGTH, sizeof(char));
    pass_hashWsalt = calloc(1, sizeof(hashed_pass_t));

    if (pass_hashWsalt == NULL) {
      perror("Calloc");
      return;
    }

    fprintf(stdout, "Create a new Master Password\n");
    printf("New Password: ");

    fgets(new_passd, PASSLENGTH, stdin);
    if (strlen(new_passd) > PASSLENGTH) {
      fprintf(stderr, "Password Too Long\n");
      return;
    }

    printf("Confirm Password: ");
    fgets(temp_passd, PASSLENGTH, stdin);

    if (strcmp(new_passd, temp_passd) != 0) {
      fprintf(stderr, "Password Do Not Match\n");
      goto free_mm;
    }

    randombytes_buf(pass_hashWsalt->salt, crypto_pwhash_SALTBYTES);

    if ((master_fp = fopen("auth.db", "wb")) == NULL) {
      perror("Fail To open AUTH_DB");
      goto free_mm;
    }

    new_passd[strlen(new_passd) - 1] = '\0';
    generate_key_pass_hash(NULL, pass_hashWsalt->hash, new_passd, NULL, 1);

    fwrite(pass_hashWsalt, sizeof(hashed_pass_t), 1, master_fp);
    fclose(master_fp);
    goto free_mm;

  free_mm:
    free(new_passd);
    free(temp_passd);
    free(pass_hashWsalt);
    return;
  }
}
