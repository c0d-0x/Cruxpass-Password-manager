#include "password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
// [TODO] cleanup needed, request_mem implementation not necessary
char *passTmp;
char *unameTmp;
password_t *password_Tmp;

int request_mem(void) {
  // I've reused the same variables in 2 functions, hence the need for a
  // function
  passTmp = malloc(sizeof(char) * DESCLENGTH);
  unameTmp = malloc(sizeof(char) * ACCLENGTH);
  password_Tmp = malloc(sizeof(password_t));

  if (passTmp == NULL || unameTmp == NULL || password_Tmp == NULL) {
    perror("Memory Allocation");
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

  size_t i = 0;
  char *token, *saveptr;
  char buffer[BUFFMAX];
  password_t *password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation");
    return;
  }

  while (fgets(buffer, BUFFMAX, fp) != NULL) {

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
      buffer[len - 1] = '\0'; // Replace newline with null terminator
    }

    token = strtok_r(buffer, ",", &saveptr);
    if (strlen(token) > PASSLENGTH) {
      fprintf(stderr, "Password at line %ld is more than %d characters\n", i,
              PASSLENGTH);
      i++;
      continue;
    }
    // Refactor for portability [TODO]
    strncpy(password->passd, token, PASSLENGTH);
    token = strtok_r(NULL, ",", &saveptr);

    if (strlen(token) > PASSLENGTH) {
      fprintf(stderr, "username Name at line %ld is more than %d characters\n",
              i, ACCLENGTH);
      i++;
      continue;
    }
    strncpy(password->username, token, ACCLENGTH);

    token = strtok_r(NULL, ",", &saveptr);

    if (strlen(token) > DESCLENGTH) {
      fprintf(stderr,
              "Password description at line %ld is more than %d characters\n",
              i, DESCLENGTH);
      i++;
      continue;
    }

    strncpy(password->description, token, DESCLENGTH);
    fwrite(password, sizeof(password_t), 1, database_ptr);
    i++;
  }
  fclose(fp);
  fclose(database_ptr);
  free(password);
}
