# Crypt

Crypt encrypts and decrypts files in a secure manner using a password.

## Usage

	crypt {/e|/d} <input>

	/e      - Encrypt the supplied file/directory
	/d      - Decrypt the supplied file/directory
	input   - Input file/directory

Crypt will encrypt/decrypt files in place.
As of now, the source file is not deleted upon success.

- Crypt appends `.cry` to encrypted files filenames and removes it when decrypting.
- Crypt will not encrypt already encrypted files again.

## Header structure

The header is structured as this:

| Size (in bytes) | Value                 |
| --------------- | --------------------- |
| 6               | "ACRYPT"              |
| Salt + 4        | Salt                  |
| Key hash + 4    | Key hash              |
| IV + 4          | Initialization vector |
| File hash + 4   | Source File hash      |

Apart from the first field, all fields are prefixed with a 4 byte integer that specifies their length.
The length prefix is stored in little endian.
The prefixed data is stored as raw byte arrays.
The encrypted content is directly after the header without length prefixing.

### Description of header fields

The chapters below describe the header fields

#### ACRYPT

This string is used to detect encrypted files.
This eventually allows the tool to work without the `.cry` file extension.
It's in uppercase and not null terminated.

#### Salt

This is the salt value that is used for the Password derivation function.

This is stored "as-is".
It is needed this way to generate the hashes and is unique to each encrypted file.
It ensures that all hashes are unique to each file
and prevents an attacker from finding the original file faster.

By default it is as large as the largest possible key size of the crypto stream algorithm but can be of virtually any size.
It's randomly chosen.

#### Key hash

This is the hash that can be used to check if a password is valid or not.

This is the SHA256 of the final password hash.
Because of the salt, this is unique to each file too.

#### IV

This is the initialization vector for the cryptostream.

This is stored as-is since the cryptostream needs it this way.
It is unique to each file and ensures that encrypting the same file with the same key will yield different results.
This prevents an attacker from detecting if source files of two encrypted files were identical.

#### File hash

This is the hash that can be used to check if the decryption was successfull.

The hash is generated using an SHA256-HMAC of the original hash and the Salt.
Because the salt is different for each file, this will also different each time the same file is encrypted.
We do not use the unmodified source file hash as it would allow possible lookup of the source file.

## Security

### Password input

The password input in the console is masked and does not allows stream redirection.
It can't be passed via argument.

### Algorithms

#### Random

Random bytes are chosen using cryptographically secure algorithms,
either using the respective functions of components in use or the `RNGCryptoServiceProvider` where not available.

#### Password

The method to get the Key bytes from the password in use is PBKDF2 using 50'000 rounds.
This algorithm is specified in [RFC 2898](https://www.rfc-editor.org/info/rfc2898).

Usually only 10'000 or less rounds are chosen.
A higher number of rounds slows down each attempt to get the key bytes,
but will not have an impact on the performance of the crypto stream.

#### File Hash

The hash is generated using an SHA256-HMAC of the original hash (SHA256) and the Salt.

#### Encryption

The crypto stream uses Rijndael (AES) using the maximum allowed keysize.









