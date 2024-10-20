/**
 *  \file Lab2.c
 *  \brief Implements encryption and decription of files. 
 *  Expected encrypted data input / output format is hexadecimal string.
 */

#include <getopt.h>
#include <libakrypt.h>
#include <stdbool.h>
#include <stdio.h>

#define ARGUMENT_LENGTH 32
#define FILE_LENGTH 2048

/**
 *  \brief Writes contents of the buffer to the specified file.
 *  Exits, if any errors occur while opening the file or writing to it.
 *  @param buffer Buffer, which will be written to the file.
 *  @param buffer_size Size of the buffer.
 *  @param path File, which will be filled with the contents of the buffer.
 */
void write_file(const char *buffer, size_t buffer_size, const char *path) {
  FILE *file = fopen(path, "wb");
  if (file == NULL) {
    fprintf(stderr, "Error opening file: %s\n", path);
    exit(EXIT_FAILURE);
  }
  size_t bytes_written = fwrite(buffer, 1, buffer_size, file);
  if ((bytes_written != buffer_size) || ferror(file)) {
    fprintf(stderr, "Error writing to file: %s\n", path);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
}

/**
 *  \brief Reads contents of the file to the buffer.
 *  Exits, if any errors occur while opening or reading the file.
 *  @param buffer Buffer, which will be filled with the contents of the file.
 *  @param buffer_size Size of the buffer.
 *  @param path File, from which the buffer will be filled.
 */
void read_file(char *buffer, size_t buffer_size, const char *path) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "Error opening file: %s\n", path);
    exit(EXIT_FAILURE);
  }
  size_t bytes_read = fread(buffer, 1, buffer_size, file);
  if ((bytes_read == 0 && !feof(file)) || ferror(file)) {
    fprintf(stderr, "Error reading file: %s\n", path);
  fclose(file);
  exit(EXIT_FAILURE);
  }
  fclose(file);
}

/**
 *  \brief Applications entry point.
 *  @param argc Number of external arguments.
 *  @param argv Pointers to external arguments.
 *  @return Termination status.
 */
int main(int argc, char** argv) {
  if (argc < 5) {
    fprintf(stderr, "-p and -i options are required\n");
    return EXIT_FAILURE;
  }

  int option;
  char password[ARGUMENT_LENGTH];
  char inputFile[ARGUMENT_LENGTH];
  char outputFile[ARGUMENT_LENGTH];
  memset(password, 0, ARGUMENT_LENGTH);
  memset(inputFile, 0, ARGUMENT_LENGTH);
  memset(outputFile, 0, ARGUMENT_LENGTH);

  bool inputFileFlag = true;
  bool passwordFlag = true;
  bool outputFileFlag = true;
  bool decryptionFlag = true;

  /// Use getopt to analyze external arguments.
  while ((option = getopt(argc, argv, "p:i:o:d")) != -1) {
    switch(option) {
      /// -p Required option. Additional argument - the password.
      case 'p':
        snprintf(password, ARGUMENT_LENGTH, "%s", optarg);
        passwordFlag = false;
        break;
      /// -i Required option. Additional argument - the name of the file to be encrypted.
      case 'i':
        snprintf(inputFile, ARGUMENT_LENGTH, "%s", optarg);
        inputFileFlag = false;
        break;
      /// -o Facultative option. Additional argument - the name of the file to store generated data. "encrypted/decrypted" by default.
      case 'o':
        snprintf(outputFile, ARGUMENT_LENGTH, "%s", optarg);
        outputFileFlag = false;
        break;
      /// -d Signals that the input data is encrypted and should be decrypted.
      case 'd':
        decryptionFlag = false;
        break;
      case ':':
        fprintf(stderr, "Argument required\n");
        return EXIT_FAILURE;
      case '?':
        fprintf(stderr, "Unknown option\n");
        return EXIT_FAILURE;
    }
  }
  if (passwordFlag || inputFileFlag) {
    fprintf(stderr, "Either -p or -i were not specified\n");
    return EXIT_FAILURE;
  }

  /// Create libakrypt.
  if(ak_libakrypt_create(NULL) != ak_true) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

  char fileBuf[FILE_LENGTH];
  memset(fileBuf, 0, FILE_LENGTH);

  /// Fill buffer with the contents of the file.
  read_file(fileBuf, FILE_LENGTH, inputFile);
  size_t size = strlen(fileBuf);

  /// Create and set kuznechik key.
  struct bckey ctx;
  ak_bckey_create_kuznechik(&ctx);
  ak_bckey_set_key_from_password(&ctx, password, ARGUMENT_LENGTH, "saltyval", 8);
  ak_uint8 iv[8] = {0xf0, 0xce, 0xab, 0x90, 0x78,0x56, 0x34, 0x12};
  
  if(decryptionFlag) {

    /// Encrypt data using created key.
    if(ak_bckey_ctr(&ctx, fileBuf, fileBuf, sizeof(fileBuf), iv, sizeof(iv)) != ak_error_ok) {
      fprintf(stderr, "Encryption error\n");
      ak_bckey_destroy(&ctx);
      ak_libakrypt_destroy();
      return EXIT_FAILURE;
    }

    /// Write encrypted data to file as a hexadecimal string.
    write_file(ak_ptr_to_hexstr( fileBuf, size, ak_false ), size*2, outputFileFlag ? "encrypted" : outputFile);
  } else {
    char encBuf[FILE_LENGTH];
    memset(encBuf, 0, FILE_LENGTH);
    ak_hexstr_to_ptr(fileBuf, encBuf, size / 2, ak_false);
    /// Decrypt data using created key.
    if(ak_bckey_ctr(&ctx, encBuf, encBuf, sizeof(encBuf), iv, sizeof(iv)) != ak_error_ok) {
      fprintf(stderr, "Decryption error\n");
      ak_bckey_destroy(&ctx);
      ak_libakrypt_destroy();
      return EXIT_FAILURE;
    }

    /// Write decrypted data to file.
    write_file(encBuf, size / 2, outputFileFlag ? "decrypted" : outputFile);
  }

  /// Destroy context of the key & libakrypt instance.
  ak_bckey_destroy(&ctx);
  ak_libakrypt_destroy();
  return EXIT_SUCCESS;
}
