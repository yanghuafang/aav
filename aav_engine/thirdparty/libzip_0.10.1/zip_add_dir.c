/*
  zip_add_dir.c -- add directory
  Copyright (C) 1999-2009 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>

#include "zipint.h"

/* NOTE: Signed due to -1 on error.  See zip_add.c for more details. */

ZIP_EXTERN zip_int64_t zip_add_dir(struct zip *za, const char *name) {
  int len;
  zip_int64_t ret;
  char *s;
  struct zip_source *source;

  if (ZIP_IS_RDONLY(za)) {
    _zip_error_set(&za->error, ZIP_ER_RDONLY, 0);
    return -1;
  }

  if (name == NULL) {
    _zip_error_set(&za->error, ZIP_ER_INVAL, 0);
    return -1;
  }

  s = NULL;
  len = strlen(name);

  if (name[len - 1] != '/') {
    if ((s = (char *)malloc(len + 2)) == NULL) {
      _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
      return -1;
    }
    strcpy(s, name);
    s[len] = '/';
    s[len + 1] = '\0';
  }

  if ((source = zip_source_buffer(za, NULL, 0, 0)) == NULL) {
    free(s);
    return -1;
  }

  ret = _zip_replace(za, -1, s ? s : name, source);

  free(s);
  if (ret < 0) zip_source_free(source);

  return ret;
}
