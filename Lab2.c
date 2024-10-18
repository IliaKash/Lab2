#include <libakrypt.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>

#define LENGTH sizeof(char) * (64)
#define LENGTH sizeof(char) * (64)

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

void read_file(char *buffer, char* path) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    fprintf(stderr, "Error opening file: %s\n", path);
    exit(EXIT_FAILURE);
  }

  size_t bytes_read = fread(buffer, 1, 8096, file);
  if ((bytes_read == 0 && !feof(file)) || ferror(file)) {
    fprintf(stderr, "Error reading file: %s\n", path);
    fclose(file);
    exit(EXIT_FAILURE);
  }

  fclose(file);
}

int main(int argc, char** argv) {
  if (argc < 5) {
    printf("-p and -f options are required\n");
    return EXIT_FAILURE;
  }
  ak_uint8 iv[8] = {0x03, 0x07, 0xae, 0xf1};
  struct bckey ctx;
  int option;
  char *password = malloc(LENGTH);
  char *inputFile = malloc(LENGTH);
  char *outputFile = malloc(LENGTH);
  memset(password, 0, LENGTH);
  memset(inputFile, 0, LENGTH);
  memset(outputFile, 0, LENGTH);

  bool inputFileFlag = true;
  bool passwordFlag = true;
  bool outputFileFlag = true;

  while ((option = getopt(argc, argv, "p:i:o:")) != -1) {
    switch(option) {
      case 'p':
        snprintf(password, LENGTH, "%s", optarg);
        passwordFlag = false;
        break;
      case 'i':
        snprintf(inputFile, LENGTH, "%s", optarg);
        inputFileFlag = false;
        break;
      case 'o':
        snprintf(outputFile, LENGTH, "%s", optarg);
        outputFileFlag = false;
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


  char *fileBuf = malloc(1024);
  memset(fileBuf, 0, 1024);
  char *encBuf = malloc(1024);
  memset(encBuf, 0, 1024);

  if(ak_libakrypt_create(NULL) != ak_true) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }
  read_file(fileBuf, inputFile);
  ak_bckey_create_kuznechik(&ctx);
  ak_bckey_set_key_from_password(&ctx, password, 64, "pepper", 6);
  
  if(ak_bckey_ctr(&ctx, fileBuf, encBuf, 1024, iv, 8) != ak_error_ok) {
    printf("Encryption error\n");
    ak_bckey_destroy(&ctx);
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }
  printf("%s\n", encBuf);
  memset(fileBuf, 0, 1024);
  printf("%s\n", fileBuf);
  write_file(encBuf, outputFileFlag ? "encrypted" : outputFile);
  if(ak_bckey_ctr(&ctx, encBuf, fileBuf, 1024, iv, 8) != ak_error_ok) {
    printf("Decryption error\n");
    ak_bckey_destroy(&ctx);
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }
  printf("%s\n", fileBuf);
  write_file(fileBuf, "ebtel");

  free(fileBuf);
  free(password);
  free(inputFile);
  free(outputFile);
  ak_bckey_destroy(&ctx);
  ak_libakrypt_destroy();
  return EXIT_SUCCESS;
}
