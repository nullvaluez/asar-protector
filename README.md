# asar-protector

This Node.js script enhances the security of ASAR archives using encryption, bloating, checksum embedding, and optional honeytoken embedding. It utilizes native bindings through `ffi-napi` and cryptographic functions to secure the archives against tampering and unauthorized access.

## Dependencies

- `ffi-napi`: To load and utilize custom native functions for encryption, bloating, and checksum calculations.
- `archiver`: To handle the creation and management of archive files.
- `fs`: Node's native file system module for reading and writing files.
- `crypto`: To perform cryptographic operations.
- `yargs`: To parse command line arguments and options.

## Native Bindings

The script loads a native module that provides the following functions:

- `encrypt(string, string)`: Encrypts data using a provided password.
- `bloat(string, size_t)`: Adds non-functional data to the encrypted data to increase its size.
- `checksum(string)`: Generates a checksum of the provided data.

## Functionality

### `hardenAsar(srcPath, dstPath, password, bloatSize, stealthMode, honeytoken)`

This asynchronous function hardens an ASAR archive as follows:

1. **Read ASAR contents**: Loads the ASAR file specified by `srcPath`.
2. **Calculate checksum**: Computes a checksum of the original ASAR data.
3. **Encrypt data**: Encrypts the ASAR data using the provided password.
4. **Bloating**: Increases the size of the encrypted data by adding non-functional data, specified by `bloatSize`.
5. **Honeytoken embedding**: If a honeytoken is provided, it embeds this data into the bloated data.
6. **Anti-tampering**: Combines the original checksum and the bloated (and potentially honeytoken-embedded) data to form the final protected data.
7. **Create new ASAR archive**: Creates a new ASAR archive containing the protected data and saves it using the `dstPath`.
8. **Logging**: Outputs the status of the operation to the console.

### Command Line Interface

The script can be executed from the command line with specific options:

- `--src`: Source ASAR archive path (required).
- `--dst`: Destination path for the hardened ASAR archive (required).
- `--password`: Password for encryption (required).
- `--bloatSize`: Size of the bloat data in bytes (required).
- `--stealth`: Enables stealth mode (optional).
- `--honeytoken`: Data to be embedded as a honeytoken (optional).

## Example Usage

```bash
node [script_name] harden --src="./path/to/source.asar" --dst="./path/to/destination.asar" --password="securepassword" --bloatSize=1024 --stealth --honeytoken="exampleToken"