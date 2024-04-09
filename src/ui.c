#include "cruxpass.h"
#include <ncurses.h>

char *getpass_custom(char *prompt) {

  char *temp_passd = calloc(PASSLENGTH, sizeof(char));
  if (temp_passd == NULL) {
    perror("calloc");
    return NULL;
  }

  initscr();
  int max_y, max_x;
  WINDOW *win = NULL;
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
    pat = wgetch(win);
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
  int rows, cols, page_height, page_width;
  WINDOW *page;
  int current_line = 1;

  initscr();
  noecho();
  clear();
  curs_set(0);
  getmaxyx(stdscr, rows, cols);

  page_height = rows - 2; /*Adjust for borders*/
  page_width = cols - 2;

  if ((page = newwin(page_height, page_width, 1, 1)) ==
      NULL) { /* Create window with 1px border*/
    echo();
    endwin();
    fclose(password_db);
    remove(".temp_password.db");
    free(password_s);
  }

  printw("\tID\tUsername\t\t\t\tPassword\t\t\t\tDescription\n");
  refresh();
  while (fread(password_s, sizeof(password_t), 1, password_db) == 1) {
    box(page, 0, 0);
    if (current_line >= page_height - 1) {
      wrefresh(page);
      mvprintw(page_height + 1, 1, "Press any key for next page");
      getch();
      wclear(page);
      current_line = 1;
    }

    mvwprintw(page, current_line, 1, "\t%ld\t%s\t\t\t%s\t\t\t%s\n",
              password_s->id, password_s->username, password_s->passd,
              password_s->description);
    current_line++;
  }
  wrefresh(page);
  getch(); // Wait for a key press before exiting
  echo();
  endwin();

  fclose(password_db);
  remove(".temp_password.db");
  free(password_s);
}
