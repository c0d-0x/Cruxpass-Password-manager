void *random_password(void);
void save_password(const char *password,
                   const char *account); // takes in random_password as argument
                                         // then saves in a database.
void *authentication(void *); // takes in a an address of the master password.
