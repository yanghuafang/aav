#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* init_occ(const char* p, char* occ) {
  assert(p != NULL && occ != NULL);

  for (int i = 0; i < 256; ++i) occ[i] = -1;

  int m = strlen(p);
  for (int i = 0; i < m; ++i) occ[p[i]] = i;

  return occ;
}

int sunday_matcher(const char* t, const char* p) {
  if (NULL == t || NULL == p) return -1;
  int n = strlen(t);
  int m = strlen(p);
  if (0 == n || 0 == m || n < m) return -1;

  char occ[256];
  init_occ(p, occ);

  int t_begin = 0;
  int t_end = m - 1;

  int ret = -1;
  while (t_end < n) {
    int i = 0;
    while (i < m) {
      if (t[t_end - i] == p[(m - 1) - i])
        ++i;
      else
        break;
    }
    if (i == m) {
      printf("p %s occurs at &t[%d] %s\n", p, t_begin, &t[t_begin]);
      ret = 0;
      break;
      ++t_begin;
      ++t_end;
    } else {
      if (t_end == n - 1) break;
      char next_char = t[t_end + 1];
      if (-1 == occ[next_char])
        t_begin = t_end + 2;
      else {
        int move_distance = (t_end + 1) - (t_begin + occ[next_char]);
        t_begin += move_distance;
      }
      t_end = t_begin + (m - 1);
    }
  }
  // printf("\n");
  return ret;
}

#if 0
int main(int argc, char* argv[])
{
    sunday_matcher("0127174527127174127", "27174");
    sunday_matcher("ababcabcabc", "abcabc");
    sunday_matcher("ABCDEABCDGABCDETTABCDFABCDETTABCDATYUABCD", "ABCDETT");

    sunday_matcher("ababcabababab", "ab");
    sunday_matcher("abababababa", "aba");
    sunday_matcher("xababcabababab", "ab");
    sunday_matcher("aaaaaa", "aaa");
    sunday_matcher("aaaaaa", "aa");
    sunday_matcher("aaaaaa", "a");
    sunday_matcher("a", "a");
    sunday_matcher("a", "");
    sunday_matcher("", "a");
    sunday_matcher("", "");

    sunday_matcher("abcabdabcabc", "aacaac");
    sunday_matcher("abcabdabcabc", "abcabc");
    sunday_matcher("abdabcabcab", "abcab");
    sunday_matcher("abcabcab", "abcab");
    sunday_matcher("xababcabababab", "abcabab");
    return 0;
}
#endif
