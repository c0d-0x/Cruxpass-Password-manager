#include <stdio.h>
#define PASSLENGTH 35
#define ACCLENGTH 30
#define BUFFMAX PASSLENGTH *ACCLENGTH

typedef struct {
  char pass[PASSLENGTH];
  char account[PASSLENGTH];
} password_t;

void *random_password(void);
void save_password(const password_t *password,
                   FILE *database_ptr); // takes in random_password as argument
                                        // then saves in a database.
void *authentication(
    void *master_pass); // takes in a an address of the master password.
void list_all_passwords(FILE *database_ptr);
void export_pass(FILE *database_ptr, const char *export_file);
void import_pass(FILE *database_ptr, const char *import_file);
