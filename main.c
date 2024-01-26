#include "password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
FILE *database_ptr;
void help() {
  printf("Syntax: cruxPass <option> <Search / password> <username "
         "only with -s >\n");

  printf(" -h: shows this help\n -s: stores a password\n -r: "
         "generates "
         "a random password\n -c: searches a password by username\n -l: list "
         "all saved "
         "passwords\n");
}

int main(int argc, char *argv[]) {
  password_t *password;
  if (argc < 2) {
    help();
    return 1;
  }

  if (strncmp(argv[1], "-h", sizeof(char) * 2) == 0) {

    help();
  } else if (strncmp(argv[1], "-s", sizeof(char) * 2) == 0) {

    if (argc != 4) {
      fprintf(stderr, " usage: %s <-s> <password> <account or username>",
              argv[0]);
      return 1;
    }
    if ((strlen(argv[2]) > PASSLENGTH) || (strlen(argv[3]) > ACCLENGTH)) {
      fprintf(stderr, "MAX PASSLENGTH: %d & MAX ACCLENGTH: %d\n", PASSLENGTH,
              ACCLENGTH);
    }

    strcpy(password->pass, argv[2]);
    strcpy(password->account, argv[3]);
    save_password(password, database_ptr);

    // Authenication
    // writing to the Database

  } else if (strncmp(argv[1], "-l", sizeof(char) * 2) == 0) {

    // Authenication
    // list all passwords stored in the Database.
    list_all_passwords(database_ptr);

  } else if (strncmp(argv[1], "-r", sizeof(char) * 2) == 0) {

    void *password = random_password();
    printf("%s\n", (char *)password);
    free(password);
  } else if (strncmp(argv[1], "-c", sizeof(char) * 2) == 0) {
    if (argc != 3) {
      fprintf(stderr, " usage: %s <-s> <account or username>", argv[1]);
    }

    // Authenication to the Database
    // call shearch for password
  } else if (strncmp(argv[1], "-e", sizeof(char) * 2) == 0) {
    if (argc != 3) {
      fprintf(stderr, " usage: %s <-e> <csv file>", argv[1]);
    }
    export_pass(database_ptr, argv[2]);
  } else if (strncmp(argv[1], "-i", sizeof(char) * 2) == 0) {
    if (argc != 3) {
      fprintf(stderr, " usage: %s <-i> <csv file>", argv[1]);
    }
    import_pass(database_ptr, argv[2]);
  }

  return EXIT_SUCCESS;
}
