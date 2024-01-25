// verif_cookie.h
#ifndef VERIF_COOKIE_H
#define VERIF_COOKIE_H

#include <curl/curl.h>
#include <string.h>
#include <stdio.h>

void verify_cookies(const char *url, char *result, size_t result_size);

#endif // VERIF_COOKIE_H
