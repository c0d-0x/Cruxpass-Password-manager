#include "cruxpass.h"

static size_t set_id() {
  FILE *password_db;
  if ((password_db = fopen(".temp_password.db", "rb")) == NULL) {
    perror("Fail to open password_db");
    return 0;
  }

  size_t temp_id = 0;
  password_t *temp_pass = NULL;
  temp_pass = malloc(sizeof(password_t));

  if (temp_pass == NULL) {
    perror("Memory Allocation Fail");
    fclose(password_db);
    return 0;
  }

  /*Seek to the end of the file*/
  if (fseek(password_db, -(long)sizeof(password_t), SEEK_END) == 0) {
    /* Read the last password structure*/
    if (fread(temp_pass, sizeof(password_t), 1, password_db) == 1) {
      temp_id = temp_pass->id + 1;
    }
  } else {
    temp_id = 1;
  }

  free(temp_pass);
  fclose(password_db);
  return temp_id;
}

void help() {
  printf("\tusage: cruxPass <option> <password> <username--optional--> "
         "<description>\n");

  printf(
      "\t-h: shows this help\n \t-s: stores a password\n \t-r: "
      "generates "
      "a random password and takes no arguments\n \t-d: deletes a password by "
      "id\n \t-n: creates a new master password\n \t-l: list "
      "all saved "
      "passwords and takes no arguments \n \t-e: Exports all passwords to a "
      "csv file\n \t-i: imports "
      "passwords from a csv file\n");
}

char *random_password(int password_len) {
  if (password_len < PASS_MIN || password_len > PASSLENGTH) {
    printf("Password must be at least 8 & 35 characters long\n");
    return NULL;
  }
  char pass_bank[] = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
      'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
      'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4',
      '5', '6', '7', '8', '9', '#', '%', '&', '(', ')', '_', '+', '=', '{',
      '}', '[', '-', ']', ':', '<', '@', '>', '?'};
  int bank_len = strlen(pass_bank);
  char *password = NULL;
  password = malloc(sizeof(char) * password_len);
  if (password == NULL) {
    perror("Fail to creat password");
    return NULL;
  }

  if (sodium_init() == 1) {
    free(password);
    fprintf(stderr, "Error: Failed to initialize libsodium");
    return NULL;
  }

  for (int i = 0; i < password_len; i++) {
    password[i] += pass_bank[(int)randombytes_uniform(bank_len)];
  }
  return password;
}

void *setpath(char *home_file_path) {
  char *path = NULL;
  if ((path = calloc(256, sizeof(char))) == NULL) {
    return NULL;
  }
  char *home = getenv("HOME");
  if (home == NULL) {
    free(path);
    return NULL;
  }

  sprintf(path, "%s", home);
  strncat(path, home_file_path, (246 - strlen(home)));
  path[strlen(path)] = '\0';
  return path;
}

/**
 * decrypts a file and return a key for encryption.
 */
unsigned char *decryption_logic() {

  char *master_passd = NULL;
  unsigned char *key;
  hashed_pass_t *hashed_password;

  char *path = setpath(PATH);
  if (chdir(path) != 0) {
    fprintf(stderr, "Not DB Directory Found. [Run: make install]\n");
    free(path);
    return NULL;
  }

  free(path);
  if (sodium_init() == -1) {
    fprintf(stderr, "Error: Failed to initialize libsodium");
    return NULL;
  }

  if ((key = (unsigned char *)sodium_malloc(sizeof(unsigned char) * KEY_LEN)) ==
      NULL) {
    perror("Memory Allocation Fail");
    return NULL;
  }

  if ((master_passd = getpass_custom("Master Password: ")) == NULL) {
    sodium_memzero(key, KEY_LEN);
    sodium_free(key);
    return NULL;
  }

  if ((hashed_password = authenticate(master_passd)) == NULL) {
    sodium_memzero(key, KEY_LEN);
    sodium_memzero(master_passd, PASSLENGTH);
    sodium_free(key);
    free(master_passd);
    return NULL;
  }

  if (generate_key_pass_hash(key, NULL, master_passd, hashed_password->salt,
                             0) != 0) {
    sodium_memzero(key, KEY_LEN);
    sodium_memzero(master_passd, PASSLENGTH);
    sodium_free(key);
    free(hashed_password);
    free(master_passd);
    return NULL;
  }

  if (access("password.db", F_OK) != 0) {
    free(hashed_password);
    sodium_memzero(master_passd, PASSLENGTH);
    free(master_passd);
    return key;
  }

  if (decrypt(".temp_password.db", "password.db", key) != 0) {
    fprintf(stderr, "Fail to decrypt PASSWORD_DB");
    sodium_memzero(key, KEY_LEN);
    sodium_memzero(master_passd, PASSLENGTH);
    free(hashed_password);
    free(master_passd);
    sodium_free(key);
    return NULL;
  }

  sodium_memzero(master_passd, PASSLENGTH);
  free(hashed_password);
  free(master_passd);

  return key;
}

static void encryption_logic(unsigned char *key) {
  remove("password.db");
  if (encrypt("password.db", ".temp_password.db", key) != 0) {
    fprintf(stderr, "Fail to encrypt PASSWORD_DB\n");
    return;
  }

  sodium_memzero(key, KEY_LEN);
  sodium_free(key);
  remove(".temp_password.db");
}

int save_password(password_t *password, FILE *password_db) {
  unsigned char *key;
  if ((key = decryption_logic()) == NULL) {
    return EXIT_FAILURE;
  }
  if ((password_db = fopen(".temp_password.db", "ab+")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    sodium_memzero(key, KEY_LEN);
    sodium_free(key);
    return EXIT_FAILURE;
  }

  size_t id_last_pass = set_id();
  if (id_last_pass == 0) {
    fprintf(stderr, "Fail to set an id\n");
    fclose(password_db);
    sodium_memzero(key, KEY_LEN);
    sodium_free(key);
    return EXIT_FAILURE;
  }

  password->id = id_last_pass;
  if (fwrite(password, sizeof(password_t), 1, password_db) != 1) {
    perror("Fail to save password");
    fclose(password_db);
    sodium_memzero(key, KEY_LEN);
    sodium_free(key);
    return EXIT_FAILURE;
  }

  fclose(password_db);
  encryption_logic(key);
  return EXIT_SUCCESS;
}

int export_pass(FILE *password_db, const char *export_file) {
  unsigned char *key;
  if ((key = decryption_logic()) == NULL) {
    return EXIT_FAILURE;
  }

  FILE *fp;
  if ((fp = fopen(export_file, "wb")) == NULL) {
    perror("Fail to Export");
    sodium_memzero(key, KEY_LEN);
    remove(".temp_password.db");
    sodium_free(key);
    return EXIT_FAILURE;
  }

  if ((password_db = fopen(".temp_password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    sodium_memzero(key, KEY_LEN);
    remove(".temp_password.db");
    sodium_free(key);
    return EXIT_FAILURE;
  }

  password_t *password = NULL;
  if ((password = malloc(sizeof(password_t))) == NULL) {
    perror("Memory Allocation Fail");
    sodium_memzero(key, KEY_LEN);
    remove(".temp_password.db");
    sodium_free(key);
    return EXIT_FAILURE;
  }

  fputs("Username,Password,Description\n", fp);
  while (fread(password, sizeof(password_t), 1, password_db) == 1) {
    fprintf(fp, "%s,%s,%s\n", password->username, password->passd,
            password->description);
  }

  fclose(fp);
  fclose(password_db);
  encryption_logic(key);
  free(password);
  return EXIT_SUCCESS;
}

/**
 * @field: password_t field
 * @max_length: field MAX, a const
 * @field_name: for error handling
 * @line_number also for error handling
 */
static int process_field(char *field, const int max_length, char *token,
                         const char *field_name, size_t line_number) {
  if (token == NULL) {
    fprintf(stderr, "Missing %s at line %ld\n", field_name, line_number);
    return EXIT_FAILURE;
  }
  if ((const int)strlen(token) > max_length) {
    fprintf(stderr, "%s at line %ld is more than %d characters\n", field_name,
            line_number, max_length);
    return EXIT_FAILURE;
  }
  strncpy(field, token, max_length);
  return EXIT_SUCCESS;
}

void import_pass(FILE *password_db, char *import_file) {

  if (access(import_file, F_OK) != 0) {
    perror("Fail to import passwords");
    return;
  }

  FILE *fp;
  if ((fp = fopen(import_file, "r")) == NULL) {
    perror("Fail to import passwords");
    free(import_file);
    return;
  }

  unsigned char *key;
  if ((key = decryption_logic()) == NULL) {
    fclose(fp);
    free(import_file);
    return;
  }

  if ((password_db = fopen(".temp_password.db", "ab+")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    sodium_memzero(key, KEY_LEN);
    free(import_file);
    sodium_free(key);
    fclose(fp);
    return;
  }

  size_t line_number = 1;
  char *saveptr;
  char buffer[BUFFMAX + 1];
  password_t *password = NULL;
  password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation");
    sodium_memzero(key, KEY_LEN);
    free(import_file);
    sodium_free(key);
    fclose(fp);
    return;
  }

  size_t id = set_id();
  if (id == 0) {
    fprintf(stderr, "could not set an id\n");
    sodium_memzero(key, KEY_LEN);
    free(import_file);
    sodium_free(key);
    free(password);
    fclose(fp);
    return;
  }

  while (fgets(buffer, BUFFMAX, fp) != NULL) {
    buffer[strcspn(buffer, "\n")] = '\0'; /*Remove trailing newline*/

    if (process_field(password->username, ACCLENGTH,
                      strtok_r(buffer, ",", &saveptr), "Username",
                      line_number) != 0) {
      line_number++;
      continue;
    }

    if (process_field(password->passd, PASSLENGTH,
                      strtok_r(NULL, ",", &saveptr), "Password",
                      line_number) != 0) {
      line_number++;
      continue;
    }

    if (process_field(password->description, DESCLENGTH,
                      strtok_r(NULL, ",", &saveptr), "Description",
                      line_number) != 0) {
      line_number++;
      continue;
    }
    password->id = id;
    fwrite(password, sizeof(password_t), 1, password_db);
    id++;
    line_number++;
  }
  fclose(fp);
  fclose(password_db);
  encryption_logic(key);
  free(import_file);
  free(password);
  return;
}

int delete_password(FILE *password_db, size_t id) {

  FILE *temp_bin = NULL;
  password_t *password = NULL;
  int password_deleted = 0;
  password = malloc(sizeof(password_t));

  if (password == NULL) {
    perror("Memory Allocation");
    return EXIT_FAILURE;
  }

  unsigned char *key;
  if ((key = decryption_logic()) == NULL) {
    fprintf(stderr, "could not generate key\n");
    free(password);
    fclose(temp_bin);
    remove(".temp.db");
    return EXIT_FAILURE;
  }

  if ((temp_bin = fopen(".temp.db", "wb")) == NULL) {
    perror("File Error");
    free(password);
    return EXIT_FAILURE;
  }

  if ((password_db = fopen(".temp_password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    free(password);
    remove(".temp_password.db");
    remove(".temp.db");
    fclose(temp_bin);
    return EXIT_FAILURE;
  }

  while (fread(password, sizeof(password_t), 1, password_db) == 1) {

    if (password->id == id) {
      printf("ID: %ld\nUsername: %s\nPassword: %s\nDescription: %s\n<Password "
             "Deleted>\n",
             password->id, password->username, password->passd,
             password->description);
      password_deleted = 1;
      continue;
    }
    /* updating IDs */
    if (password_deleted) {
      password->id--;
    }

    fwrite(password, sizeof(password_t), 1, temp_bin);
  }

  fclose(password_db);
  fclose(temp_bin);

  if (password_deleted) {
    remove(".temp_password.db");
    rename(".temp.db", ".temp_password.db");
    free(password);
    encryption_logic(key);
  } else {
    sodium_memzero(key, KEY_LEN);
    sodium_free(key);
    free(password);
    remove(".temp_password.db");
    remove(".temp.db");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
