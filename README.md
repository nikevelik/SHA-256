# SHA256
This is console application, implementing hashing of TEXT with SHA256, part of Secure Hash Algorithm 2. 

The application has the following functionalities:
- reading a message from a file
- hashing a message using SHA-256
- saving a hashed message to a file
- hashed message reading - determine if a submitted hash matches the hash of a read message

## Code documentation:

### Helper Functions
1. addWithCarry - Incrementation of a number, handle overflow by incrementing the carry.
    - The addWithCarry function is necessary to keep track of the total bit length of the input data processed by the SHA-256 algorithm. The bit length is an integral part of the SHA-256 algorithm, and it influences the finalization steps and ensures that the entire message length is taken into account when computing the hash.

2. getRightRotation - Circular right rotation - shift right and wrap the shifted bits on the left.
3. getChooseBitByBit -  the x input chooses if the output is from y or from z. More precisely, for each bit position, that result bit is according to the bit from y (or respectively z ) at this position, depending on if the bit from x at this position is 1 (or respectively 0).
4. getBitwiseMajority - If a minimum 2 of 3 bits at position n in inputs x, y, z are 1, the majority of bits is considered 1. Thus, bit at position n in result will be 1. Otherwise 0.

### SHA 256 Logical Functions
1. Big Sigma 0: fundamental constant function in the SHA-256 algorithm. It involves circular right rotations of the input 'x' at specific bit positions (2, 13, and 22). EP0 contributes to the non-linearity and diffusion properties required for secure cryptographic hash generation.

2. Big Sigma 1: another crucial constant function in the SHA-256 algorithm. Similar to EP0, it performs circular right rotations on the input 'x' at specific bit positions (6, 11, and 25). EP1 plays a vital role in enhancing the cryptographic strength of the hash function.

3. Small Sigma 0: an essential constant function that integrates circular right rotations and bit-wise shifting operations. It operates on the input 'x' at specific bit positions (7, 18, and 3) to introduce further complexity and security to the SHA-256 algorithm.

4. Small Sigma 1: a critical constant function in the SHA-256 algorithm, similar to SIG0. It applies circular right rotations and bit-wise shifting operations to the input 'x' at specified bit positions (17, 19, and 10). SIG1 contributes to the overall robustness and cryptographic properties of the hash function.

### Constants
1. ROUND_CONSTANTS (K0-K63): SHA-256 uses a set of 64 constant 32-bit words (K0, K1, ..., K63) during the processing of each 512-bit block of the input message. These constants are derived from the fractional parts of the cube roots of the first 64 prime numbers.
2. INITIAL_HASHES (0-8): starting values for every (32-bit) hash subpart (they make up the whole 256 bit hash)
3. HASH_LEN - 64.
4. HEX_CHARS - string/array of chars that contains the corresponding hex digit to numbers 0-15



### File I/O

1. saveHashToFile


    0. The `saveHashToFile` function is designed to save a hash string, represented by `hash_str`, to a file specified by the `file` parameter. The hash string is assumed to have a length of `HASH_LEN` characters. 

    1. Parameters

        - `hash_str` (const char*): A pointer to the hash string to be saved to the file.
        - `file` (const char*): A pointer to the file path where the hash string will be saved.

    2. Return Value

        - `bool`: The function returns `true` if the saving process is successful, and `false` if either the `hash_str` or `file` pointer is null, the file cannot be opened, or there is an issue writing the hash string to the file.

    3. Implementation Details

        - The function begins by checking for null pointers in the `hash_str` and `file` parameters. If either pointer is null, the function returns `false`. The hash string is then written to the specified file using an `ofstream` object. The hash string is written using the `write` method. The function checks if the write operation was successful and closes the file accordingly.


2. getHashFromFile 


    0. The `getHashFromFile` function is designed to read the first `HASH_LEN` symbols from a specified file and store them in a character array provided as the `dest` parameter. The function returns a boolean value, indicating whether the operation was successful or not.

    1. Parameters

        - `file` (const char*): The path to the file from which the hash message will be read.
        - `dest` (char*): A pointer to the destination character array where the hash message will be stored.

    2. Return Value

        - `bool`: The function returns `true` if the operation is successful, and `false` if either the `file` path or the `dest` pointer is null, the file cannot be opened, or if the read operation fails.

    3. Implementation Details

        - The function uses an `ifstream` to open the specified file. If the file opening is successful, it reads the first `HASH_LEN` symbols from the file into the `dest` array. The function checks for errors during the read operation and ensures that the read length matches the expected `HASH_LEN`. If any error occurs, the function sets `dest[0]` to the null terminator and returns `false`. Otherwise, it adds a null terminator at the end of the hash message in `dest` and closes the file.

### SHA functions
1. SHA256 
    0. The `SHA256` function is the main component of the SHA-256 hashing algorithm, which generates a secure 256-bit hash (32-byte hash) from the given input string. The resulting hash is stored in the character array provided by the `dest` parameter.

    1. Parameters
        - `input_str` (const char*): The input string to be hashed.
        - `dest` (char*): A pointer to the destination character array where the resulting hash will be stored.

    2. Return Value
        - `bool`: The function returns `true` if the hashing process is successful, and `false` if either the `dest` pointer or the `input_str` is null.
    
    3. Implementation Details
        1. Input Validation:
            - The function checks if the destination pointer (`dest`) and the input string pointer (`input_str`) are not null. If either is null, the function returns `false`.

        2. Initialization:
            - The function initializes a data buffer (`dataBuffer`) to store each 64-symbol block of the input.
            - It tracks the last iterated symbol in the block (`idxInBuffer`) and the total bits iterated (`bitlen`).
            - The sub-hashes (`subhashes`) are initialized with the initial hash values (`INITIAL_HASHES`).

        3. SHA256 Update:
            - The function calls the `SHA256Update` function to process the input string in 64-symbol blocks, updating the sub-hashes accordingly. If the update fails, the function returns `false`.

        4. SHA256 Finalization:
            - The function calls the `SHA256Final` function to include bias in the hash based on the input length, updating the sub-hashes. If the finalization fails, the function returns `false`.

        5. Conversion to String:    
            - The function calls the `subhashesToStr` function to convert the sub-hashes into a hash string. If the conversion fails, the function returns `false`.

        6. Success:
            - If all steps are completed successfully, the function returns `true`.



2. SHA256File Function Documentation
    0. The `SHA256File` function serves as the main entry point for computing the SHA-256 hash of a file. It takes the file path as input, processes the file in 64-symbol blocks, and produces the final hash, which is then stored in the character array provided as the `dest` parameter.

    1. Parameters

        - `file` (const char*): The path to the file for which the SHA-256 hash is to be computed.
        - `dest` (char*): A pointer to the destination character array where the resulting hash string will be stored.

    2. Return Value

        - `bool`: The function returns `true` if the SHA-256 hash computation is successful, and `false` under the following conditions:
        - If the `dest` pointer is null.
        - If the `file` pointer is null.
        - If there is an issue with the SHA-256 file update process.
        - If there is an issue with the finalization of the SHA-256 computation.
        - If there is an issue converting the subhashes to a hash string.

    3. Implementation Details

        The function utilizes a series of variables to manage the file processing and hash computation:
        - `dataBuffer`: A container for each 64-symbol block of the input file.
        - `idxInBuffer`: Keeps track of the last iterated symbol in the block.
        - `bitlen`: An array to keep track of the total bits iterated.
        - `subhashes`: An array representing the sub-hashes, initialized with predefined values.

        The function initializes the sub-hashes and proceeds to update them through the `SHA256FileUpdate` function, which processes the file in blocks. After the file is fully processed, the final SHA-256 computation is performed using the `SHA256Final` function. Finally, the resulting subhashes are converted to a hash string using the `subhashesToStr` function.

2. subhashesToStr
    0. The `subhashesToStr` function is designed to convert an array of 8 subhashes, each represented as a 4-byte word, into a single hash string. The resulting hash string is stored in a character array provided as the `dest` parameter. The hash string is represented in hexadecimal format.
    1. Parameters
        - `subhashes` (unsigned int[8]): An array containing 8 subhashes, each represented as a 4-byte word.
        - `dest` (char*): A pointer to the destination character array where the resulting hash string will be stored.
    2. Return Value
        - `bool`: The function returns `true` if the conversion is successful, and `false` if either the `dest` pointer or the `subhashes` array is null.

    3. Implementation Details
        - The function iterates through each byte position (0 to 3) in the 4-byte words and each subhash in the `subhashes` array. For each byte, it extracts the byte at the specified position, calculates the corresponding index in the destination array (`dest`), and converts the byte to a hexadecimal representation. The resulting hash string is formed by concatenating the hexadecimal representations of the bytes.

3. SHA256Final
    0. The `SHA256Final` function is responsible for finalizing the SHA-256 hash computation. It includes padding the input data, updating the bit length based on the input length, and incorporating a bias in the hash calculation. The final hash is updated in the `subhashes` array.
    
    1. Parameters
        - `dataBuffer` (unsigned char*): A pointer to the input data buffer.
        - `idxInBuffer` (unsigned int): The index indicating the current position in the data buffer.
        - `bitlen` (unsigned int[2]): A 64-bit array representing the bit length of the input data.
        - `subhashes` (unsigned int[8]): An array containing 8 subhashes.
    2. Return Value
        - `bool`: The function returns `true` if the finalization process is successful and `false` if any of the input pointers (`dataBuffer`, `bitlen`, or `subhashes`) is null.
    3. Implementation Details
        - The function first checks for null pointers in the input parameters. It then determines whether there is enough space in the data buffer for padding. If there is sufficient space, padding is added directly. If not, a transformation is performed first before padding.
        - The bit length is incremented based on the input length, and the updated bit length is added to the next transformation. The `SHA256Transform` function is called twice, once before padding and once after, to update the subhashes with the bias included.

4. SHA256Transform

    0. The `SHA256Transform` function implements the SHA-256 hashing algorithm to transform an array of input data into 8 subhashes. The input data is represented as an array of 64 elements, each with values ranging from 0 to 256. The resulting subhashes are stored in the provided `subhashes` array.

    1. Parameters

        - `data` (const unsigned char*): A pointer to the input data array containing 64 elements with values in the range 0-256.
        - `subhashes` (unsigned int[8]): An array representing the 8 subhashes that will be updated by the transformation.

    2. Return Value

        - `bool`: The function returns `true` if the transformation is successful, and `false` if either the `data` pointer or the `subhashes` array is null.

    3. Implementation Details

        - The function begins by validating the input parameters. It then initializes variables for the index of the 32-bit word in the message schedule (`wordIdx`), the index of the character in the input data (`charIdx`), and the message schedule array (`messageSchedule`). Additionally, it sets up an array (`subhashIncrement`) to store values added to the subhashes.

        - The input data is processed and expanded into the message schedule, following the SHA-256 algorithm specifications. The function then performs a series of calculations to determine the values to add to the subhashes, based on the previous values, round constants, and the message schedule. The subhashes are updated accordingly in each iteration.

5. SHA256Step

    0. The `SHA256Step` function performs a step in the SHA-256 hashing algorithm. It updates the state of the hash, represented by the `subhashes` array, based on the data provided in the `dataBuffer`. Additionally, it increments the total bit length processed so far, stored in the `bitlen` array.

    1. Parameters

        - `dataBuffer` (unsigned char*): A pointer to the input data block to be processed.
        - `bitlen` (unsigned int[2]): An array representing the total bit length processed so far. It is updated during the function execution.
        - `subhashes` (unsigned int[8]): An array representing the current state of the hash. It is updated based on the input data.

    2. Return Value

        - `bool`: The function returns `true` if the step is successfully completed, and `false` if the underlying SHA256 transformation (`SHA256Transform`) fails.

    3. Implementation Details

        1. The function first updates the hash state (`subhashes`) by calling the `SHA256Transform` function with the provided `dataBuffer`. If the transformation fails, the function returns `false`.

        2. It then increments the total bit length processed (`bitlen`) by adding 512 bits. This accounts for the 512 bits processed in the current data block.

        3. The function returns `true` to indicate a successful step in the SHA-256 algorithm.

6.  SHA256Update 

    0. The `SHA256Update` function is responsible for iterating through an input string and updating the SHA-256 subhashes and bit length after processing every 512-bit block (64 characters) of the input. The function maintains a data buffer (`dataBuffer`) to accumulate the input block before passing it to the SHA-256 stepping function (`SHA256Step`). The `idxInBuffer` parameter keeps track of the current position in the buffer.

    1. Parameters

        - `dataBuffer` (unsigned char*): A buffer to accumulate the input string in 512-bit blocks.
        - `input_str` (const unsigned char*): The input string to be processed.
        - `idxInBuffer` (unsigned int&): A reference to the current index in the data buffer.
        - `bitlen` (unsigned int[2]): An array containing the current bit length of the input message.
        - `subhashes` (unsigned int[8]): An array representing the SHA-256 subhashes.

    2. Return Value
        - `bool`: The function returns `true` if the update is successful, and `false` if any of the input parameters (`input_str`, `dataBuffer`, `bitlen`, or `subhashes`) is null or if the SHA256Step function fails.

    3. Implementation Details

        - The function iterates through each character in the input string, saving it to the data buffer and updating the index (`idxInBuffer`). After every 64 characters (512 bits), it invokes the `SHA256Step` function to update the SHA-256 subhashes and bit length. The process continues until the entire input string is processed.

7. SHA256FileUpdate
    0. The `SHA256FileUpdate` function is responsible for iterating through the input string represented by a file, updating the subhashes and bit length after processing each 512-bit block (64 characters) from the file. This function utilizes the `SHA256Step` function to perform the hash computation for each block.

    1. Parameters

        - `dataBuffer` (unsigned char*): A buffer used to store the input data read from the file.
        - `file` (const char*): The path to the input file to be processed.
        - `idxInBuffer` (unsigned int&): A reference to a variable that stores the number of characters in the incomplete last block.
        - `bitlen` (unsigned int[2]): An array representing the bit length of the input data processed so far.
        - `subhashes` (unsigned int[8]): An array containing 8 subhashes used in the hash computation.

    2. Return Value

        - `bool`: The function returns `true` if the file is successfully opened and processed, updating the subhashes and bit length for each 512-bit block. It returns `false` if any of the input parameters are null or if an error occurs during file processing.

    3. Implementation Details

        - The function opens the specified file and reads data from it in 64-character (512-bit) blocks. For each block, the `SHA256Step` function is called to update the subhashes and bit length. The index of the incomplete last block (`idxInBuffer`) is then stored for future reference.

        - After processing the entire file, the file stream is closed.

8. compareHashes

    0. The `compareHashes` function is designed to compare two hash strings, `hash1` and `hash2`, to determine if they match. The function returns `true` if the hashes are identical and `false` otherwise.

    1. Parameters

        - `hash1` (const char*): A pointer to the first hash string to be compared.
        - `hash2` (const char*): A pointer to the second hash string to be compared.

    2. Return Value

        - `bool`: The function returns `true` if the hash strings match, and `false` if either `hash1` or `hash2` is null or if the hash strings differ.

    3. Implementation Details

        - The function iterates through each character in the hash strings and checks if the corresponding characters at the same position are equal. If any pair of characters differs, the function returns `false`, indicating that the hashes do not match. If the loop completes without finding any differences, the function returns `true`.
