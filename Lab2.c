/**
 *  \file Lab2.c
 *  \brief Implements encryption and decription of files.
 */

#include <getopt.h>
#include <libakrypt.h>
#include <stdio.h>
#include <stdbool.h>

#ifndef PASS_LENGTH
#define PASS_LENGTH sizeof(char) * (33)
#endif
#ifndef FILE_LENGTH
#define FILE_LENGTH 1024
#endif

/**
 *  \brief Writes contents of the buffer to the specified file.
 *  Exits, if any errors occur while opening the file or writing to it.
 *  @param buffer Buffer, which will be written to the file.
 *  @param path File, which will be filled with the contents of the buffer. 
 */
void write_file(char *buffer, const char *path) {
  FILE *file = fopen(path, "w");
  if (file == NULL) {
    fprintf(stderr, "Error opening file: %s\n", path);
    exit(EXIT_FAILURE);
  }

  size_t bytes_written = fwrite(buffer, 1, strlen(buffer), file);
  if ((bytes_written != strlen(buffer)) || ferror(file)) {
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
 *  @param path File, from which the buffer will be filled.
 */
void read_file(char *buffer, char *path) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    fprintf(stderr, "Error opening file: %s\n", path);
    exit(EXIT_FAILURE);
  }

  size_t bytes_read = fread(buffer, 1, FILE_LENGTH, file);
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
    printf("-p and -f options are required\n");
    return EXIT_FAILURE;
  }

  int option;
  char password[PASS_LENGTH];
  char inputFile[PASS_LENGTH];
  char outputFile[PASS_LENGTH];
  memset(password, 0, PASS_LENGTH);
  memset(inputFile, 0, PASS_LENGTH);
  memset(outputFile, 0, PASS_LENGTH);

  bool inputFileFlag = true;
  bool passwordFlag = true;
  bool outputFileFlag = true;
  bool decryptionFlag = true;

  /// Use getopt to analyze external arguments.
  while ((option = getopt(argc, argv, "p:i:o:d")) != -1) {
    switch(option) {
      /// -p Required option. Additional argument - the password.
      case 'p':
        snprintf(password, PASS_LENGTH, "%s", optarg);
        passwordFlag = false;
        break;
      /// -i Required option. Additional argument - the name of the file to be encrypted.
      case 'i':
        snprintf(inputFile, PASS_LENGTH, "%s", optarg);
        inputFileFlag = false;
        break;
      /// -o Facultative option. Additional argument - the name of the file to store encrypted data. "encrypted" by default.
      case 'o':
        snprintf(outputFile, PASS_LENGTH, "%s", optarg);
        outputFileFlag = false;
        break;
      /// -d Facultative option. Enables decryption of encrypted data. The result is stored in file "decrypted".
      case 'd':
        decryptionFlag = false;
        break;
      case ':':
        printf("Argument required\n");
        return EXIT_FAILURE;
      case '?':
        printf("Unknown option\n");
        return EXIT_FAILURE;
    }
  }
  if (passwordFlag || inputFileFlag) {
    printf("Either -p or -f were not specified\n");
    return EXIT_FAILURE;
  }

  char fileBuf[FILE_LENGTH];
  memset(fileBuf, 0, FILE_LENGTH);
  char encBuf[FILE_LENGTH];
  memset(encBuf, 0, FILE_LENGTH);
  read_file(fileBuf, inputFile);

  /// Create libakrypt.
  if(ak_libakrypt_create(NULL) != ak_true) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }
  /// Fill buffer with the contents of the file.
  read_file(fileBuf, inputFile);

  /// Create kuznechik key.
  ak_uint8 iv[8] = {0x03, 0x07, 0xae, 0xf1};
  struct bckey ctx;
  ak_bckey_create_kuznechik(&ctx);
  ak_bckey_set_key_from_password(&ctx, password, PASS_LENGTH, "pepper", 6);

  /// Encrypt data using created key.
  if(ak_bckey_ctr(&ctx, fileBuf, encBuf, FILE_LENGTH, iv, 8) != ak_error_ok) {
    printf("Encryption error\n");
    ak_bckey_destroy(&ctx);
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

  /// Write encrypted data to file.
  write_file(encBuf, outputFileFlag ? "encrypted" : outputFile);
  if(!decryptionFlag) {

    /// Serves the purpose of deleting the contents of fileBuf. Is unnecessary, just like encBuf.
    /// It is done to clearly demonstrate that the decrypted data originates from encrypted data.
    memset(fileBuf, 0, FILE_LENGTH);

    /// Decrypt data.
    if(ak_bckey_ctr(&ctx, encBuf, fileBuf, FILE_LENGTH, iv, 8) != ak_error_ok) {
      printf("Decryption error\n");
      ak_bckey_destroy(&ctx);
      ak_libakrypt_destroy();
      return EXIT_FAILURE;
    }
    /// Write decrypted data to file.
    write_file(fileBuf, "decrypted");
  }

  ak_bckey_destroy(&ctx);
  ak_libakrypt_destroy();
  return EXIT_SUCCESS;
}
