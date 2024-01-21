#include "password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

void save_password(const password_t *password, FILE *file_ptr) {
  if ((file_ptr = fopen("password.bin", "ab")) == NULL) {
    perror("Password Database");
    return;
  };

  // calls deccrypt function to deccrypt the database
  // hash the password.
  //
  if (fwrite((void *)password, sizeof(password_t), 1, file_ptr) != 1) {
    perror("Writing to password.bin");
  };
  // ecrypt the file back
  fclose(file_ptr);
}

void list_all_passwords(FILE *file_ptr) {
  if ((file_ptr = fopen("password.bin", "rb")) == NULL) {
    perror("cannot read password db");
    return;
  }
  password_t *password = malloc(sizeof(password_t));
  if (password == NULL) {
    perror("memory allocation fail");
    return;
  }
  while (fread(password, sizeof(password_t), 1, file_ptr) == 1) {
    fprintf(stdout, "Password: %s\tAccount: %s\n", password->pass,
            password->account);
  }
  fclose(file_ptr);
  free(password);
}
