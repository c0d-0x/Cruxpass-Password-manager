#ifndef CRUXPASS_H
#define CRUXPASS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>

#define CHUNK_SIZE 4096
#define IDLENGTH 13
#define PASSLENGTH 35
#define ACCLENGTH 30
#define DESCLENGTH 56
#define BUFFMAX PASSLENGTH + ACCLENGTH + DESCLENGTH

typedef struct {
  size_t id;
  char passd[PASSLENGTH + 1];
  char username[ACCLENGTH + 1];
  char description[DESCLENGTH + 1];
} password_t;

void help();
char *random_password(void);
int delete_password(FILE *, size_t);
int save_password(password_t *password,
                  FILE *database_ptr); // takes in random_password as argument
                                       // then saves in a database.
int authentication(
    void *master_passd); // takes in a an address of the master password.
void list_all_passwords(FILE *database_ptr);
int export_pass(FILE *database_ptr, const char *export_file);
void import_pass(FILE *database_ptr, const char *import_file);

#endif
