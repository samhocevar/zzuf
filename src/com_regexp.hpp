#ifndef COM_REGEXP_HPP
#define COM_REGEXP_HPP


/* ref: http://code.google.com/p/tinysegmenter-cpp */

typedef struct  regex_s
{
    void        *cxx_regex;
}               regex_t;

typedef struct  regmatch_s
{
    void        *cxx_regmatch;
}               regmatch_t;

enum regexp_result
{
    REG_NOMATCH  = 1,
    REG_EXTENDED = 0x00000100
};

#ifdef __cplusplus
extern "C" {
#endif

int regcomp(regex_t *preg, const char *pattern, int cflags);
int regwcomp(regex_t *preg, const wchar_t *pattern, int cflags);
size_t regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size);
int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t *pmatch, int eflags);
int regwexec(const regex_t *preg, const wchar_t *string, size_t nmatch, regmatch_t *pmatch, int eflags);
void regfree(regex_t *preg);

#ifdef __cplusplus
}
#endif

#endif // !COM_REGEXP_HPP
