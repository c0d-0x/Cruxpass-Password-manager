#include "src/cruxpass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *password_db;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    help();
    return 1;
  }
  password_t *password = NULL;

  if (strncmp(argv[1], "-h", sizeof(char) * 2) == 0) {

    help();
  } else if (strncmp(argv[1], "-s", sizeof(char) * 2) == 0) {

    if (argc != 5) {
      fprintf(stderr, " usage: %s <-s> <password> <username> <description>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    __initcrux();
    // Authenication[TODO]
    if ((strlen(argv[2]) > PASSLENGTH) ||
        (strlen(argv[3]) > ACCLENGTH || (strlen(argv[4]) > DESCLENGTH))) {
      fprintf(stderr,
              "MAX PASSLENGTH: %d & MAX ACCLENGTH: %d & MAX DESCLENGTH: %d\n",
              PASSLENGTH, ACCLENGTH, DESCLENGTH);
      return EXIT_FAILURE;
    }

    password = malloc(sizeof(password_t));
    if (password == NULL) {
      perror("Memory allocation fail");
      return 1;
    }

    strncpy(password->passd, argv[2], PASSLENGTH);
    strncpy(password->username, argv[3], ACCLENGTH);
    strncpy(password->description, argv[4], DESCLENGTH);
    if (save_password(password, password_db) == 0) {
      printf("Password saved...\n");
      free(password);
    }

  } else if (strncmp(argv[1], "-l", sizeof(char) * 2) == 0) {

    __initcrux();

    // Authenication[TODO]
    list_all_passwords(password_db);

  } else if (strncmp(argv[1], "-r", sizeof(char) * 2) == 0) {

    char *password = random_password();
    printf("%s\n", password);
    free(password);
  } else if (strncmp(argv[1], "-e", sizeof(char) * 2) == 0) {
    if (argc != 3) {
      fprintf(stderr, " usage: %s <-e> <csv file>\n", argv[0]);
      return EXIT_FAILURE;
    }
    __initcrux();

    if (export_pass(password_db, argv[2]) == 0) {
      printf("Passwords exported to %s", argv[2]);
    };
  } else if (strncmp(argv[1], "-i", sizeof(char) * 2) == 0) {
    if (argc != 3) {
      fprintf(stderr, " usage: %s <-i> <csv file>\n", argv[0]);
      return EXIT_FAILURE;
    }
    __initcrux();

    import_pass(password_db, argv[2]);

  } else if (strncmp(argv[1], "-d", sizeof(char) * 2) == 0) {

    if (argc != 3) {
      fprintf(stderr, " usage: %s <-d> <password ID>\n", argv[0]);
      return EXIT_FAILURE;
    }

    __initcrux();
    size_t id = atoi(argv[2]);
    if (delete_password(password_db, id) != 0) {
      fprintf(stderr, "Password was not found...\n");
      return EXIT_FAILURE;
    }

  } else if (strncmp(argv[1], "-n", 3) == 0) {

    char *master_passd = NULL;
    master_passd = calloc(PASSLENGTH, sizeof(char));
    if (master_passd == NULL) {
      perror("calloc");
      return EXIT_FAILURE;
    }
    printf("Master Password: ");
    master_passd = fgets(master_passd, PASSLENGTH, stdin);
    master_passd[strlen(master_passd) - 1] = '\0';
    if (strlen(master_passd) < 8) {
      fprintf(stdin, "Invalid Password\n");
      return EXIT_FAILURE;
    }

    if (create_new_master_passd(master_passd) != 0) {
      fprintf(stderr, "Fail to Creat a New Password\n");
      return EXIT_FAILURE;
    }
  } else {
    help();
  }
  return EXIT_SUCCESS;
}
