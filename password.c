#include "password.h"
// [TODO] cleanup needed, request_mem implementation not necessary
char *passTmp = NULL;
char *unameTmp = NULL;
password_t *password_Tmp = NULL;

int request_mem(void) {
  passTmp = malloc(sizeof(char) * DESCLENGTH);
  unameTmp = malloc(sizeof(char) * ACCLENGTH);
  password_Tmp = malloc(sizeof(password_t));

  if (passTmp == NULL || unameTmp == NULL || password_Tmp == NULL) {
    perror("Memory Allocation Fail");
    return 1;
  }
  return 0;
}

void *random_password(void) {
  char pass_bank[] = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
      'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
      'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '!', '#', '$', '%', '&', '(', ')', '_',
      '+', '=', '{', '}', '[', ']', ';', ':', '<', '@', '>', '?'};
  char *password = malloc(sizeof(char) * PASSLENGTH);
  if (password == NULL) {
    perror("Fail to creat password");
    return NULL;
  }
  srand(time(NULL));
  for (size_t i = 0; i < PASSLENGTH; i++) {
    password[i] += pass_bank[rand() % strlen(pass_bank)];
  }
  return (void *)password;
}

void save_password(const password_t *password, FILE *database_ptr) {
  if ((database_ptr = fopen("password.db", "ab")) == NULL) {
    perror("Fail to read PASSWORD_DB");
    return;
  };

  // calls deccrypt function to deccrypt the database
  // hash the password.
  //
  if (fwrite((void *)password, sizeof(password_t), 1, database_ptr) != 1) {
    perror("Fail to save password");
  };
  // ecrypt the file back
  fclose(database_ptr);
}

void list_all_passwords(FILE *database_ptr) {
  if ((database_ptr = fopen("password.db", "rb")) == NULL) {
    perror("Fail to read PASSWORD_DB");
    return;
  }
  /**
   * A temp variable to print exactly the password word
   * without printing along it's username detail
   **/
  if (request_mem() == 1) {
    return;
  }
  while (fread(password_Tmp, sizeof(password_t), 1, database_ptr) == 1) {
    strncpy(passTmp, password_Tmp->passd, PASSLENGTH);
    strncpy(unameTmp, password_Tmp->username, ACCLENGTH);
    fprintf(stdout, "Username: %s\nPassword: %s\nDescription: %s\n\n", unameTmp,
            passTmp, password_Tmp->description);
  }
  fclose(database_ptr);
  free(password_Tmp);
  free(passTmp);
  free(unameTmp);
}

void export_pass(FILE *database_ptr, const char *export_file) {
  // Authenticate [TODO]

  FILE *fp;
  if ((fp = fopen(export_file, "wb")) == NULL) {
    perror("Fail to Export");
    return;
  }
  if ((database_ptr = fopen("password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    return;
  }
  if (request_mem() == 1) {
    return;
  }

  fputs("Username,Password,Description\n", fp);
  while (fread(password_Tmp, sizeof(password_t), 1, database_ptr) == 1) {

    strncpy(passTmp, password_Tmp->passd, PASSLENGTH);
    strncpy(unameTmp, password_Tmp->username, ACCLENGTH);
    fprintf(fp, " %s,%s,%s\n", unameTmp, passTmp, password_Tmp->description);
  }
  fclose(fp);
  fclose(database_ptr);
  free(password_Tmp);
  free(passTmp);
  free(unameTmp);
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
    return -1;
  }
  if (strlen(token) > max_length) {
    fprintf(stderr, "%s at line %ld is more than %d characters\n", field_name,
            line_number, max_length);
    return -1;
  }
  strncpy(field, token, max_length);
  return 0;
}

void import_pass(FILE *database_ptr, const char *import_file) {
  // Authenticate [TODO]
  if (access(import_file, F_OK) != 0) {
    perror("Fail to import passwords");
    return;
  }

  FILE *fp;
  if ((fp = fopen(import_file, "r")) == NULL) {
    perror("Fail to import passwords");
  }

  if ((database_ptr = fopen("password.db", "ab")) == NULL) {
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

    fwrite(password, sizeof(password_t), 1, database_ptr);
    line_number++;
  }
  fclose(fp);
  fclose(database_ptr);
  free(password);
}
