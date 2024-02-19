# cruxpass Password management

A simple, secure command-line password manager

## Features

Generate strong, random passwords
Store passwords securely
Retrieve passwords by username
List all saved passwords

## Usage

Bash
cruxPass <option> <argument>
Use code with caution. Learn more
Available options:

- -c: \<username\>: Search for a password by username
- -d: \<password id\>: deletes a password by id
- -e: \<file name\>: Export all saved passwords to a csv format
- -h: Display help information
- -i: '<file name>': Import passwords from a csv file
- -l: List all saved passwords
- -r: Generate a random password without storing it
- -s '<password> <username>': Generate a password and store it for the specified username

## Installation

Clone this repository:
Bash
git clone https://github.com/c0d-0x/Cruxpass-Password-manager
Use code with caution. Learn more
Compile the code:
Bash
cd cruxPass
make
Use code with caution. Learn more
Run the program:
Bash
./cruxPass <option> <argument>
Use code with caution. Learn more

## Security Considerations

Password storage: cruxPass uses a secure password storage mechanism (to be specified in detail).
Authentication: cruxPass requires authentication before accessing or modifying stored passwords.
Best practices: Always use strong, unique passwords and never share them with others.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for any suggestions or bug reports.

## License

cruxPass is licensed under the **MIT License**. See the LICENSE file for details.

## Contact

For any questions or feedback, please contact <c0d_0x007@proton.me>.

## What I HAve Learned
- string manuplation
    - Tokenization
    - 


## Additional Notes

This project is currently under development.
Future plans include:

- Encryption of stored passwords
- Support for multiple password databases
- Integration with other password management tools
