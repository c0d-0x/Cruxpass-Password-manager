#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PASSLENGTH 35
#define ACCLENGTH 30
#define DESCLENGTH 56
#define BUFFMAX PASSLENGTH + ACCLENGTH + DESCLENGTH

typedef struct {
  size_t id;
  char passd[PASSLENGTH];
  char username[ACCLENGTH];
  char description[DESCLENGTH];
} password_t;

void help();
char *random_password(void);
void *delete_password(FILE *, size_t, void *);
int save_password(password_t *password,
                  FILE *database_ptr); // takes in random_password as argument
                                       // then saves in a database.
void *authentication(
    void *master_passd); // takes in a an address of the master password.
void list_all_passwords(FILE *database_ptr);
void export_pass(FILE *database_ptr, const char *export_file);
void import_pass(FILE *database_ptr, const char *import_file);

#endif
