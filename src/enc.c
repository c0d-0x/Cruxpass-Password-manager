#include "cruxpass.h"
#include <ncurses.h>
#include <stdlib.h>

int generate_key_pass_hash(unsigned char *key, char *hashed_password,
                           const char *const new_passd, unsigned char *salt,
                           int tag) {

  if (sodium_init() == -1) {
    return EXIT_FAILURE;
  }

  switch (tag) {

  case 0:
    sodium_memzero(key, sizeof(unsigned char) * KEY_LEN);
    if (crypto_pwhash(key, sizeof(unsigned char) * KEY_LEN, new_passd,
                      strlen(new_passd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
      /* out of memory */
      perror("Could not Generate key");
      return EXIT_FAILURE;
    }
    break;
  case 1:
    sodium_memzero(hashed_password, sizeof(unsigned char) * PASS_HASH_LEN);

    if (crypto_pwhash_str(hashed_password, new_passd, strlen(new_passd),
                          crypto_pwhash_OPSLIMIT_SENSITIVE,
                          crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
      /* out of memory */
      perror("Could not Generate password hash");
      return EXIT_FAILURE;
    }
    break;
  }
  return EXIT_SUCCESS;
}

int encrypt(const char *target_file, const char *source_file,
            const unsigned char key[KEY_LEN]) {
  unsigned char buf_in[CHUNK_SIZE];
  unsigned char
      buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;
  FILE *fp_t, *fp_s;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag;

  fp_s = fopen(source_file, "rb");
  fp_t = fopen(target_file, "wb");
  crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
  fwrite(header, 1, sizeof header, fp_t);
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
    eof = feof(fp_s);
    tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
    crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in,
                                               rlen, NULL, 0, tag);
    fwrite(buf_out, 1, (size_t)out_len, fp_t);
  } while (!eof);
  fclose(fp_t);
  fclose(fp_s);
  return 0;
}

int decrypt(const char *target_file, const char *source_file,
            const unsigned char key[KEY_LEN]) {
  unsigned char
      buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char buf_out[CHUNK_SIZE];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;
  FILE *fp_t, *fp_s;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  int ret = 1;
  unsigned char tag;

  fp_s = fopen(source_file, "rb");
  fp_t = fopen(target_file, "wb");
  fread(header, 1, sizeof header, fp_s);
  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
    perror("Fail to initialize cryto_state");
    goto ret; /* incomplete header */
  }
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
    eof = feof(fp_s);
    if (crypto_secretstream_xchacha20poly1305_pull(
            &st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {
      fprintf(stderr, "Fail to load encrypted buffer\n");
      goto ret; /* corrupted chunk */
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      if (!eof) {
        goto ret; /* end of stream reached before the end of the file */
      }
    } else { /* not the final chunk yet */
      if (eof) {
        goto ret; /* end of file reached before the end of the stream */
      }
    }
    fwrite(buf_out, 1, (size_t)out_len, fp_t);
  } while (!eof);

  ret = 0;
ret:
  fclose(fp_t);
  fclose(fp_s);
  return ret;
}

hashed_pass_t *authenticate(char *master_passd) {

  if (sodium_init() == -1) {
    return NULL;
  }
  hashed_pass_t *hashed_password = malloc(sizeof(hashed_pass_t));
  int hash_read = 0;
  FILE *master_fp;
  if (access("auth.db", F_OK) == 0) {
    if ((master_fp = fopen("auth.db", "rb")) != NULL) {

      hash_read = fread(hashed_password, sizeof(hashed_pass_t), 1, master_fp);
      if (!hash_read) {
        fprintf(stderr, "No master password found\n");
        free(hashed_password);
        fclose(master_fp);
        return NULL;
      }
    }
  } else {
    free(hashed_password);
    perror("Fail To Authencate\n");
    return NULL;
  }

  if (crypto_pwhash_str_verify(hashed_password->hash, master_passd,
                               strlen(master_passd)) != 0) {

    /* wrong password */
    free(hashed_password);
    fclose(master_fp);
    fprintf(stderr, "Wrong Password...\n");
    return NULL;
  }
  fclose(master_fp);
  return hashed_password;
}

int create_new_master_passd(char *master_passd) {
  int ret = 1;
  char *new_passd;
  char *temp_passd;
  unsigned char *key = NULL;
  hashed_pass_t *old_hashed_password = NULL;
  hashed_pass_t *new_hashed_password = NULL;
  FILE *master_fp = NULL;

  if ((old_hashed_password = authenticate(master_passd)) == NULL) {
    return EXIT_FAILURE;
  }

  new_passd = getpass_custom("New Password: ");
  if (new_passd == NULL) {
    return EXIT_FAILURE;
  }

  temp_passd = getpass_custom("Confirm New Password: ");
  if (strncmp(new_passd, temp_passd, PASSLENGTH) == 0) {
    if (sodium_init() == -1) {
      fprintf(stderr, "Error: Failed to initialize libsodium");
      return EXIT_FAILURE;
    }

    new_hashed_password = calloc(1, sizeof(hashed_pass_t));
    key = (unsigned char *)sodium_malloc(sizeof(unsigned char) * KEY_LEN);

    if (new_hashed_password == NULL || key == NULL) {
      fprintf(stderr, "Memory Allocation Fail\n");
      free(new_passd);
      free(temp_passd);
      free(old_hashed_password);
      return EXIT_FAILURE;
    }

    randombytes_buf(new_hashed_password->salt,
                    sizeof(unsigned char) * SALT_HASH_LEN);

    if (generate_key_pass_hash(NULL, (char *)new_hashed_password->hash,
                               (const char *const)new_passd, NULL, 1) != 0) {

      fprintf(stderr, "Fail to generate Hash\n");
      goto free_all;
    }

    if (access("password.db", F_OK) != 0) {
      if ((master_fp = fopen("auth.db", "wb")) == NULL) {
        perror("Fail To open AUTH_DB");
        goto free_all;
      }

      fwrite(new_hashed_password, sizeof(hashed_pass_t), 1, master_fp);
      fclose(master_fp);
      perror("PASSWORD_DB not found");
      ret = 0;
      goto free_all;
    }

    if (generate_key_pass_hash(key, NULL, master_passd,
                               (unsigned char *)old_hashed_password->salt,
                               0) != 0) {
      fprintf(stderr, "Fail KEY\n");
      goto free_all;
    }

    if (decrypt(".temp_password.db", "password.db", key) != 0) {
      fprintf(stderr, "Fail to decrypt PASSWORD_DB\n");
      goto free_all;
    }

    if (generate_key_pass_hash(key, NULL, new_passd, new_hashed_password->salt,
                               0) != 0) {
      fprintf(stderr, "Fail to Create New Password:KEY_GEN\n");
      remove(".temp_passord.db");
      goto free_all;
    }

    rename("password.db", "password.db_backup");
    if (encrypt("password.db", ".temp_password.db", key) != 0) {
      fprintf(stderr, "Fail to Create New Password: F_ENCRYPTION\n");
      rename("password.db_backup", "password.db");
      goto free_all;
    }

    if ((master_fp = fopen("auth.db", "wb")) == NULL) {
      perror("Fail To open AUTH_DB");
      goto free_all;
    }

    fwrite(new_hashed_password, sizeof(hashed_pass_t), 1, master_fp);
    fclose(master_fp);

    remove("password.db_backup");
    remove(".temp_password.db");
  } else {
    fprintf(stderr, "Passwords do not march\n");
    return ret;
  }

  ret = 0;
free_all:
  sodium_memzero(key, KEY_LEN);
  sodium_free(key);
  free(old_hashed_password);
  free(new_hashed_password);
  free(new_passd);
  free(temp_passd);
  return ret;
}

static void backup_choice(void) {
  char opt;
  initscr();
  do {
    printw("Do you want to backup your old password database [Y/N]?");
    refresh();
    opt = getch(); /* Read character and convert to lowercase */
  } while ('y' == opt);

  if (opt == 'y') {
    if (rename("password.db", "password_backup.db") != 0) {
      perror("Error renaming file");
      return;
    }
    printf(" Old Password Database save\n");
  } else {

    if (remove("password.db") != 0) {
      perror("Error deleting file");
      return;
    }
    printf("Old Password Database Deleted\n");
  }
}

void __initcrux() {
  int master_opened = 0;
  char *path = setpath(PATH);
  printf(" >>>%s\n", path);
  if (chdir(path) != 0) {
    perror("Change dir");
    return;
  }

  if (access("auth.db", F_OK) != 0) {
    char *new_passd = NULL;
    char *temp_passd = NULL;
    hashed_pass_t *pass_hashWsalt = NULL;

    if (access("password.db", F_OK) == 0) {
      fprintf(stdout, "There is a PASSWORD_DB found...\n");
      backup_choice();
    }

    FILE *master_fp;
    pass_hashWsalt = calloc(1, sizeof(hashed_pass_t));
    if (pass_hashWsalt == NULL) {
      perror("Memory Allocation Fail");
      free(path);
      return;
    }

    fprintf(stdout, "Create a new Master Password\n");
    new_passd = getpass_custom("New Password: ");
    if (new_passd == NULL) {
      free(path);
      free(pass_hashWsalt);
      return;
    }

    temp_passd = getpass_custom("Confirm Password: ");
    if (strcmp(new_passd, temp_passd) != 0) {
      fprintf(stderr, "Passwords Do Not Match\n");
      goto free_mm;
    }

    randombytes_buf(pass_hashWsalt->salt, crypto_pwhash_SALTBYTES);
    if ((master_fp = fopen("auth.db", "wb")) == NULL) {
      perror("Fail To open AUTH_DB");
      goto free_mm;
    }

    if (generate_key_pass_hash(NULL, pass_hashWsalt->hash, new_passd, NULL,
                               1) != 0) {
      fprintf(stderr, "Fail to generate Hash\n");
      goto free_mm;
    }

    fwrite(pass_hashWsalt, sizeof(hashed_pass_t), 1, master_fp);

  free_mm:
    if (master_opened)
      fclose(master_fp);
    free(new_passd);
    free(temp_passd);
    free(pass_hashWsalt);
    return;
  }
}
