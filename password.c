#include "password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void *random_password(void) {
  char pass_bank[] = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
      'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
      'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '!', '#', '$', '%', '^', '&', '(', ')',
      '_', '+', '=', '{', '}', '[', ']', ';', ':', '<', '>', '?'};
  char *password = malloc(sizeof(char) * PASSLENGTH);
  if (password == NULL) {
    perror("fail to creat password");
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
    perror("Password Database");
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
    perror("Fail to open PASSWORD_DB");
    return;
  }
  password_t *password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation");
    return;
  }
  char *temp = malloc(sizeof(char) * PASSLENGTH);
  // i was having touble reading only the password without the it's correponding
  // username
  while (fread(temp, PASSLENGTH, 1, database_ptr) == 1) {
    strncpy(password->pass, temp, PASSLENGTH);
    memset(temp, '\0', PASSLENGTH);
    fread(temp, PASSLENGTH, 1, database_ptr);
    strncpy(password->account, temp, ACCLENGTH);
    fprintf(stdout, "Password: %s\tAccount: %s\n", password->pass,
            password->account);
  }
  fclose(database_ptr);
  free(password);
}

void export_pass(FILE *database_ptr, const char *export_file) {
  // Authenticate

  FILE *fp;
  if ((fp = fopen(export_file, "wb")) == NULL) {
    perror("Fail to Export");
    return;
  }
  if ((database_ptr = fopen("password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    return;
  }
  password_t *password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation");
    return;
  }
  fputs("Password,Account\n", fp);
  while (fread(password, sizeof(password_t), 1, database_ptr) == 1) {
    fprintf(fp, "%s,%s\n", password->pass, password->account);
  }
  fclose(fp);
  fclose(database_ptr);
}

void import_pass(FILE *database_ptr, const char *import_file) {
  // Authenticate
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

  int i = 0;
  char *token, *saveptr;
  token = malloc(sizeof(char) * 40);
  char buffer[BUFFMAX + 2];
  password_t *password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("Memory Allocation");
    return;
  }

  while (fgets(buffer, BUFFMAX, fp) != NULL) {

    token = strtok_r(buffer, ",", &saveptr);
    if (strlen(token) > PASSLENGTH) {
      fprintf(stderr, "Password at line %d is more than 35 characters\n", i);
      i++;
      continue;
    }

    strncpy(password->pass, token, PASSLENGTH);
    token = strtok_r(NULL, ",", &saveptr);

    if (strlen(token) > PASSLENGTH) {
      fprintf(stderr, "Account Name at line %d is more than 30 characters\n",
              i);
      i++;
      continue;
    }

    strncpy(password->account, token, ACCLENGTH);
    fwrite(password, sizeof(password_t), 1, database_ptr);
    i++;
  }
  fclose(fp);
  fclose(database_ptr);
}
