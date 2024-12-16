#include "libapk_export.h"

#include <stdio.h>

#include <new>

#include "ApkScanner.h"
using namespace std;

int libapk_createInstance(IScanner** scanner) {
  if (NULL == scanner) return -1;

  *scanner = new (nothrow) ApkScanner;
  if (NULL == *scanner) return -1;

  return 0;
}
