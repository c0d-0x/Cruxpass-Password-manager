#include "cruxpass.h"
#include <ncurses.h>

char *getpass_custom(char *prompt) {
  /* [TODO] Disable Terminal echo*/
  char *temp_passd = calloc(PASSLENGTH, sizeof(char));
  if (temp_passd == NULL) {
    perror("calloc");
    return NULL;
  }
  printf("%s", prompt);
  fgets(temp_passd, PASSLENGTH, stdin);
  temp_passd[strlen(temp_passd) - 1] = '\0';
  if (strlen(temp_passd) < 8 || strlen(temp_passd) > PASSLENGTH) {
    fprintf(stdin, "Invalid Password\n");
    return NULL;
  }
  return temp_passd;
}

void list_all_passwords(FILE *password_db) {

  unsigned char *key = NULL;
  key = decryption_logic();
  if (key == NULL) {
    return;
  }

  /*The key is never used*/
  sodium_memzero(key, KEY_LEN);
  sodium_free(key);

  if (access(".temp_password.db", F_OK) != 0) {
    fprintf(stderr, "Error: Fail to list Passwords\n");
    return;
  }

  password_t *password_s = NULL;
  password_s = calloc(1, sizeof(password_t));
  if (password_s == NULL) {
    perror("Memory Allocation Fail");
    return;
  }

  if ((password_db = fopen(".temp_password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    free(password_s);
    return;
  }
  while (fread(password_s, sizeof(password_t), 1, password_db) == 1) {

    fprintf(stdout,
            "\tID: %ld\n\tUsername: %s\n\tPassword: %s\n\tDescription: %s\n\n",
            password_s->id, password_s->username, password_s->passd,
            password_s->description);
  }
  fclose(password_db);
  remove(".temp_password.db");
  free(password_s);
}
