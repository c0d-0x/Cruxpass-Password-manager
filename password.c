#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define PASSLENGTH 30
void *random_password(void) {
  char pass_bank[] = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
      'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
      'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
      'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', '!', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '=', '{',
      '}', '[', ']', '|', ';', ':', '<', ',', '>', '?', '.', '/'};
  char *password = malloc(sizeof(char) * PASSLENGTH);
  if (password == NULL) {
    perror("fail to creat password");
    return NULL;
  }
  srand(time(NULL));
  for (size_t i = 0; i < PASSLENGTH; i++) {

    password[i] += pass_bank[rand() % strlen(pass_bank)];
    // printf("%d\n", rand() % PASSLENGTH);
  }
  return (void *)password;
}
