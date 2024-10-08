#include <ncurses.h>
#include <stdio.h>
#include <string.h>

#include "cruxpass.h"

char *getpass_custom(char *prompt) {
  char *temp_passd;
  if ((temp_passd = calloc(PASSLENGTH, sizeof(char))) == NULL) {
    perror("Fail to read password");
    return NULL;
  }

  initscr();
  int max_y, max_x;
  WINDOW *win = NULL;
  getmaxyx(stdscr, max_y, max_x);
  if ((win = newwin(3, PASSLENGTH + 2, (max_y / 2) - 2,
                    max_x / 2 - PASSLENGTH / 2)) == NULL) {
    free(temp_passd);
    endwin();
    return NULL;
  }

  refresh();
  char *ascii_tex[] = {
      "..BBBB..BBBBB..BB..BB.BB..BB.BBBBB...BBBB...BBBB...BBBB..\n",
      ".BB..BB.BB..BB.BB..BB..BBBB..BB..BB.BB..BB.BB.....BB.....\n",
      ".BB.....BBBBB..BB..BB...BB...BBBBB..BBBBB...BBBB...BBBB..\n",
      ".BB..BB.BB..BB.BB..BB..BBBB..BB.....BB..BB.....BB.....BB.\n",
      "..BBBB..BB..BB..BBBB..BB..BB.BB.....BB..BB..BBBB...BBBB..\n",
      ".........................................................\n"};
  for (size_t i = 0; i < 6; i++) {
    mvprintw(max_y * 0.22 + i + 1, max_x / 2 - PASSLENGTH + 8, "%s",
             ascii_tex[i]);
  }
  refresh();
  box(win, 0, 0);
  refresh();
  noecho();

  mvwprintw(win, 0, 0, "%s", prompt);
  refresh();
  wrefresh(win);
  move(max_y / 2 - 1, max_x / 2 - PASSLENGTH / 2 + 1);
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
    free(temp_passd);
    echo();
    endwin();
    fprintf(stderr, "Invalid password: max & min, length 35 & 8\n");
    return NULL;
  }

  echo();
  endwin();
  return temp_passd;
}

void list_all_passwords(FILE *password_db) {
  unsigned char *key = NULL;
  if ((key = decryption_logic()) == NULL) {
    return;
  }

  /*The key is never used*/
  sodium_memzero(key, KEY_LEN);
  sodium_free(key);

  if (access(".temp_password.db", F_OK) != 0) {
    fprintf(stderr, "Error: PASSWORD_DB is Empty!!!\n");
    return;
  }

  password_t *password_s = NULL;
  if ((password_s = calloc(1, sizeof(password_t))) == NULL) {
    remove(".temp_password.db");
    perror("Memory Allocation Fail");
    return;
  }

  if ((password_db = fopen(".temp_password.db", "rb")) == NULL) {
    perror("Fail to open PASSWORD_DB");
    remove(".temp_password.db");
    free(password_s);
    return;
  }

  /* printing passwords in a window*/
  size_t rows, cols, page_height, page_width;
  WINDOW *page;
  size_t current_line = 1;

  initscr();
  noecho();
  clear();
  curs_set(0);
  getmaxyx(stdscr, rows, cols);

  page_height = rows - 2; /*Adjust for borders*/
  page_width = cols * 0.85;

  if ((page = newwin(page_height, page_width, 1, cols * 0.08)) ==
      NULL) { /* Create window with 1px border*/
    echo();
    endwin();
    fclose(password_db);
    remove(".temp_password.db");
    free(password_s);
    return;
  }

  mvprintw(0, cols * 0.1,
           "\tID\t\tUsername\t\t\tPassword\t\t\t\tDescription\n");
  refresh();
  while (fread(password_s, sizeof(password_t), 1, password_db) == 1) {
    if (current_line >= page_height - 1) {
      wrefresh(page);
      mvprintw(page_height + 1, 1, "Press right any key for next page");
      getch();
      wclear(page);
      current_line = 1;
    }

    mvwprintw(page, current_line, 1, "\t%ld\t%s", password_s->id,
              password_s->username);

    mvwprintw(page, current_line, ACCLENGTH + 15, "\t%s", password_s->passd);

    mvwprintw(page, current_line, ACCLENGTH + 15 + PASSLENGTH + 5, "\t%s\n",
              password_s->description);
    current_line++;
    box(page, 0, 0);
  }
  wrefresh(page);
  getch();  // Wait for a key press before exiting
  echo();
  endwin();

  fclose(password_db);
  remove(".temp_password.db");
  free(password_s);
}
