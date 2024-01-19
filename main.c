#include "password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void help() {
  printf("Syntax: cruxPass <option> <Search / password> <username "
         "only with g>\n");

  printf(" -h: shows this help\n -g: generates a pasword to be stored\n -r: "
         "generates "
         "a random password\n -s: searches a password by username\n -l: list "
         "all saved "
         "passwords\n");
}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    help();
    return 1;
  }

  if (strncmp(argv[1], "-h", sizeof(char) * 2) == 0) {

    help();

  } else if (strncmp(argv[1], "-g", sizeof(char) * 2) == 0) {

    if (argc != 4) {
      fprintf(stderr, " usage: %s <-g> <password> <account or username>",
              argv[0]);
      return 1;
    }

    // call password generator
    // Authenication
    // writing to the Database

  } else if (strncmp(argv[1], "-l", sizeof(char) * 2) == 0) {

    // Authenication
    // list all passwords stored in the Database.

  } else if (strncmp(argv[1], "-r", sizeof(char) * 2) == 0) {

    void *password = random_password();
    printf("%s\n", (char *)password);
    free(password);
  } else if (strncmp(argv[1], "-s", sizeof(char) * 2) == 0) {
    if (argc != 3) {
      fprintf(stderr, " usage: %s <-s> <account or username>", argv[1]);
    }
  }
  // Authenication to the Database
  // call shearch for password

  return EXIT_SUCCESS;
}
