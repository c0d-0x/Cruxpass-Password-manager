#include "cruxpass.h"
#include <ncurses.h>

char *getpass_custom(char *prompt) {
  initscr();
  char *temp_passd = calloc(PASSLENGTH, sizeof(char));
  if (temp_passd == NULL) {
    perror("calloc");
    return NULL;
  }

  WINDOW *win = NULL;
  int max_y, max_x;
  getmaxyx(stdscr, max_y, max_x);
  if ((win = newwin(3, PASSLENGTH + 2, max_y / 2 + -2,
                    max_x / 2 - PASSLENGTH / 2)) == NULL) {
    endwin();
    return NULL;
  }

  refresh();
  box(win, 0, 0);
  refresh();
  noecho();
  mvwprintw(win, 0, 0, "%s", prompt);
  refresh();
  wrefresh(win);
  move(max_y / 2 + -1, max_x / 2 - PASSLENGTH / 2 + 1);
  refresh();

  unsigned int pat, i = 0;
  do {
    pat = getch();
    mvwprintw(win, 1, i + 1, "*");
    wrefresh(win);
    temp_passd[i] = pat;
    i++;
  } while (i < PASSLENGTH && pat != '\n');

  temp_passd[strlen(temp_passd) - 1] = '\0';
  if (strlen(temp_passd) < 8 || strlen(temp_passd) > PASSLENGTH) {
    fprintf(stdin, "Invalid Password\n");
    return NULL;
  }

  echo();
  endwin();
  return temp_passd;
}

void list_all_passwords(FILE *password_db) {
  // very buggy
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
  /* printing passwords in a window*/
  initscr();
  WINDOW *win_2 = NULL;
  int max_y, max_x;
  getmaxyx(stdscr, max_y, max_x);

  if ((win_2 = newwin(500, sizeof(password_t), 2, 1)) == NULL) {
    endwin();
    return;
  }
  wborder(win_2, '|', '|', '-', '-', '+', '+', '+', '+');
  wrefresh(win_2);

  while (fread(password_s, sizeof(password_t), 1, password_db) == 1) {

    mvwprintw(
        win_2, 1, 1,
        "\tID: %ld\n\tUsername: %s\n\tPassword: %s\n\tDescription: %s\n\n",
        password_s->id, password_s->username, password_s->passd,
        password_s->description);
  }
  wrefresh(win_2);
  getch();

  endwin();
  fclose(password_db);
  remove(".temp_password.db");
  free(password_s);
}
