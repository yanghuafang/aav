#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zip.h"

int unzip_file(const char* zipFilePath, const char* innerFileName,
               const char* dstFilePath) {
  if (NULL == zipFilePath || NULL == innerFileName || NULL == dstFilePath)
    return -1;

  zip* z = NULL;
  zip_file* f = NULL;
  char* contents = NULL;
  FILE* file = NULL;
  int ret = -1;
  do {
    // Open the ZIP archive
    int err = 0;
    z = zip_open(zipFilePath, 0, &err);
    if (NULL == z) break;

    // Search for the file of given name
    struct zip_stat st;
    int num_files = zip_get_num_files(z);
    if (-1 == num_files) break;
    int index = -1;
    for (int i = 0; i < num_files; i++) {
      if (-1 == zip_stat_index(z, i, 0, &st)) continue;
      if (0 == strcmp(st.name, innerFileName)) {
        index = i;
        break;
      }
    }
    if (-1 == index) break;

    // Alloc memory for its uncompressed contents
    contents = (char*)malloc(st.size);
    if (NULL == contents) break;

    // Read the compressed file
    f = zip_fopen_index(z, index, 0);
    if (NULL == f) break;
    if (-1 == zip_fread(f, contents, st.size)) break;
    zip_fclose(f);
    f = NULL;

    // And close the archive
    zip_close(z);
    z = NULL;

    file = fopen(dstFilePath, "w+");
    if (NULL == file) break;
    fwrite(contents, 1, st.size, file);
    fclose(file);
    file = NULL;

    ret = 0;
  } while (false);

  free(contents);
  contents = NULL;

  if (NULL != file) {
    fclose(file);
    file = NULL;
  }
  if (NULL != f) {
    zip_fclose(f);
    f = NULL;
  }
  if (NULL != z) {
    zip_close(z);
    z = NULL;
  }
  return ret;
}
