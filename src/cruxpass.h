/**
 * POJECT: cruxpass - A simple password manager
 * AUTHOR: c0d_0x
 * MIT LICENSE
 */

#ifndef CRUXPASS_H
#define CRUXPASS_H
#include <ctype.h>
#include <ncurses.h>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/utils.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>

#define PASS_MIN 8
#define CHUNK_SIZE 4096
#define PASSLENGTH 35
#define ACCLENGTH 30
#define DESCLENGTH 56
#define BUFFMAX PASSLENGTH + ACCLENGTH + DESCLENGTH
#define KEY_LEN crypto_box_SEEDBYTES
#define PASS_HASH_LEN crypto_pwhash_STRBYTES
#define SALT_HASH_LEN crypto_pwhash_SALTBYTES
#define PATH "/.local/share/cruxpass"

typedef struct {
  size_t id;
  char passd[PASSLENGTH + 1];
  char username[ACCLENGTH + 1];
  char description[DESCLENGTH + 1];
} password_t;

typedef struct {
  char hash[PASS_HASH_LEN + 1];
  unsigned char salt[SALT_HASH_LEN];
} hashed_pass_t;

/**
 * Prints the help menu to the terminal.
 */
void help();
void __initcrux();
/**
 * Generates a random password of the specified length.
 *
 * @param password_len the length of the password to generate
 * @return a pointer to the generated password, or NULL on failure
 */
char *random_password(int password_len);
unsigned char *decryption_logic();
void *setpath(char *);
/**
 * Deletes a password from the given file pointer.
 *
 * @param database_ptr the file pointer to the database
 * @param id the id of the password to delete
 * @return 0 on success, 1 on failure
 */
int delete_password(FILE *, size_t);

/**
 * Saves a password to the given file pointer.
 *
 * @param password the password to save
 * @param database_ptr the file pointer to the database
 * @return 0 on success, 1 on failure
 */
int save_password(password_t *password, FILE *database_ptr);

// then saves in a database.
/**
 * Takes in a master password and returns a hashed password.
 * @param master_passd the master password to hash
 * @return a hashed password
 */
hashed_pass_t *authenticate(char *master_passdm);

/**
 * Takes in a hashed password and returns a password.
 * @param hashed_passd the hashed password
 * @return a password
 */
void list_all_passwords(FILE *database_ptr);

/**
 * Exports a password from the database to a file.
 * @param database_ptr the file pointer to the database
 * @param export_file the file path to export the password to
 * @return 0 on success, 1 on failure
 */
int export_pass(FILE *database_ptr, const char *export_file);

/**
 * Exports a password from the database to a file.
 *
 * @param database_ptr the file pointer to the database
 * @param export_file the file path to export the password to
 * @return 0 on success, 1 on failure
 */
void import_pass(FILE *database_ptr, char *import_file);

/**
 * Creates a new master password for the database.
 *
 * @param master_passd the master password to hash
 * @return 0 on success, 1 on failure
 */
int create_new_master_passd(char *master_passd);

/**
 * Prompts the user for a password and returns it as a string.
 *
 * @param prompt the prompt to display to the user
 * @return the password entered by the user
 */
char *getpass_custom(char *);

/**
 * Generates a key or  password hash for encryption and decryption.
 *
 * @param key a pointer to a buffer to store the encryption key
 * @param hashed_password a pointer to a buffer to store the hashed password
 * @param new_passd the plaintext password to hash
 * @param salt a pointer to the salt for key generation
 * @param tag a flag indicating whether to generate a decryption key or not
 * @return 0 on success, 1 on failure
 */
int generate_key_pass_hash(unsigned char *key, char *hashed_password,
                           const char *const new_passd, unsigned char *salt,
                           int tag);

/**
 * Decrypts a file using the given key.
 *
 * @param target_file the path to the target file
 * @param source_file the path to the source file
 * @param key the encryption key
 * @return 0 on success, 1 on failure
 */
int decrypt(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

/**
 * Encrypts a file using the given key.
 *
 * @param target_file the path to the target file
 * @param source_file the path to the source file
 * @param key the encryption key
 * @return 0 on success, 1 on failure
 */
int encrypt(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

#endif
