#include <stdio.h>
#define PASSLENGTH 35
#define ACCLENGTH 30

typedef struct {
  char pass[PASSLENGTH];
  char account[PASSLENGTH];
} password_t;

void *random_password(void);
void save_password(const password_t *password,
                   FILE *file_ptr); // takes in random_password as argument then
                                    // saves in a database.
void *authentication(
    void *master_pass); // takes in a an address of the master password.
void list_all_passwords(FILE *file_ptr);
