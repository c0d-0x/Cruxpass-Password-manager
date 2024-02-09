#include "password.h"
#include <stdlib.h>

static size_t set_id() {
  FILE *password_db;
  if ((password_db = fopen("password.db", "rb")) == NULL) {
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

  // Seek to the end of the file
  if (fseek(password_db, -(long)sizeof(password_t), SEEK_END) == 0) {
    // Read the last password structure
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
  printf("Syntax: cruxPass <option> <password> <username--optional--> "
         "<description>\n");

  printf(" -h: shows this help\n -s: stores a password\n -r: "
         "generates "
         "a random password and takes no arguments\n -d: deletes a password by "
         "id\n -c: searches a password "
         "by username\n -l: list "
         "all saved "
         "passwords and takes no arguments \n -e: Exports all passwords to a "
         "csv file\n -i: imports "
         "passwords from a csv file\n");
}

char *random_password(void) {
  char pass_bank[] = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
      'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
      'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '!', '#', '$', '%', '&', '(', ')', '_',
      '+', '=', '{', '}', '[', ']', ';', ':', '<', '@', '>', '?'};

  char *password = NULL;
  password = malloc(sizeof(char) * PASSLENGTH);
  if (password == NULL) {
    perror("Fail to creat password");
    return NULL;
  }

  srand(time(NULL));
  for (size_t i = 0; i < PASSLENGTH; i++) {
    password[i] += pass_bank[rand() % strlen(pass_bank)];
  }
  return password;
}

int save_password(password_t *password, FILE *password_db) {
  if ((password_db = fopen("password.db", "ab")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    return 1;
  }

  // ... (decryption logic here)

  size_t id = set_id();
  if (id == 0) {
    fprintf(stderr, "Fail to set an id\n");
    return EXIT_FAILURE;
  }

  password->id = id;
  if (fwrite(password, sizeof(password_t), 1, password_db) != 1) {
    perror("Fail to save password");
    fclose(password_db);
    return 1;
  }

  // ... (encryption logic here)

  fclose(password_db);
  return 0;
}

void list_all_passwords(FILE *password_db) {
  if ((password_db = fopen("password.db", "rb")) == NULL) {
    perror("Fail to read PASSWORD_DB");
    return;
  }
  /**
   * A temp variable to print exactly the password word
   * without printing along it's username detail
   **/
  password_t *password = NULL;
  char *passTmp = NULL;
  char *unameTmp = NULL;
  password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation Fail");
    return;
  }

  while (fread(password, sizeof(password_t), 1, password_db) == 1) {
    passTmp = strndup(password->passd, PASSLENGTH);
    unameTmp = strndup(password->username, ACCLENGTH);

    fprintf(stdout, "ID: %ld\nUsername: %s\nPassword: %s\nDescription: %s\n\n",
            password->id, unameTmp, passTmp, password->description);
  }

  fclose(password_db);
  free(password);
  free(passTmp);
  free(unameTmp);
}

/// @brief exports passwords from the password_db to a csv file
/// @param password_db
/// @param export_file
/// @return
int export_pass(FILE *password_db, const char *export_file) {
  // Authenticate [TODO]

  FILE *fp;
  if ((fp = fopen(export_file, "wb")) == NULL) {
    perror("Fail to Export");
    return EXIT_FAILURE;
  }

  if ((password_db = fopen("password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    return EXIT_FAILURE;
  }

  password_t *password = NULL;
  char *passTmp = NULL;
  char *unameTmp = NULL;

  password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation Fail");
    return EXIT_FAILURE;
  }

  fputs("Username,Password,Description\n", fp);
  while (fread(password, sizeof(password_t), 1, password_db) == 1) {
    passTmp = strndup(password->passd, PASSLENGTH);
    unameTmp = strndup(password->username, ACCLENGTH);
    fprintf(fp, " %s,%s,%s\n", unameTmp, passTmp, password->description);
  }

  fclose(fp);
  fclose(password_db);
  free(password);
  free(passTmp);
  free(unameTmp);
  return EXIT_SUCCESS;
}

static int process_field(char *field, const int max_length, char *token,
                         const char *field_name, size_t line_number) {
  /**
   * field: password_t field
   * max_length: field MAX, a const
   * field_name: for error handling
   * line_number also for error handling
   */

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

void import_pass(FILE *password_db, const char *import_file) {
  // Authenticate [TODO]
  if (access(import_file, F_OK) != 0) {
    perror("Fail to import passwords");
    return;
  }

  FILE *fp;
  if ((fp = fopen(import_file, "r")) == NULL) {
    perror("Fail to import passwords");
  }

  if ((password_db = fopen("password.db", "ab")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    return;
  }

  size_t line_number = 1;
  char *saveptr;
  char buffer[BUFFMAX];

  password_t *password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation");
    return;
  }

  size_t id = set_id();
  if (id == 0) {
    fprintf(stderr, "could not set an id\n");
    return;
  }

  while (fgets(buffer, BUFFMAX, fp) != NULL) {
    buffer[strcspn(buffer, "\n")] = '\0'; // Remove trailing newline

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
  free(password);
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

  if ((temp_bin = fopen(".temp.db", "wb")) == NULL) {
    perror("Fail to open temp.db");
    return EXIT_FAILURE;
  }

  if ((password_db = fopen("password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    return EXIT_FAILURE;
  }

  while (fread(password, sizeof(password_t), 1, password_db) == 1) {

    if (password->id == id) {
      char *uname = strndup(password->username, ACCLENGTH);
      char *passd = strndup(password->passd, PASSLENGTH);
      char *description = strndup(password->description, DESCLENGTH);
      printf(
          "ID: %ld\nUsername: %s\nPassword: %s\nDescription: %s\nIs deleted...",
          password->id, uname, passd, description);
      password_deleted = 1;
      free(uname);
      free(passd);
      free(description);
      continue;
    }
    // updating IDs
    if (password_deleted) {
      password->id--;
    }

    fwrite(password, sizeof(password_t), 1, temp_bin);
  }

  fclose(password_db);
  fclose(temp_bin);

  if (password_deleted) {
    remove("password.db");
    rename(".temp.db", "password.db");
  } else {
    remove(".temp.db");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
