#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include "include/verif_cookie.h"


struct CookieData {
    char data[8192];
};

// Callback entete
static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    struct CookieData *cookieData = (struct CookieData *)userdata;
    size_t numBytes = size * nitems;
    const char *cookie_header = "Set-Cookie:";

    if (strncmp(buffer, cookie_header, strlen(cookie_header)) == 0) {
        strncat(cookieData->data, buffer + strlen(cookie_header), sizeof(cookieData->data) - strlen(cookieData->data) - 1);
        strncat(cookieData->data, "\n", sizeof(cookieData->data) - strlen(cookieData->data) - 1);
    }

    return numBytes;
}

// Verif des cookies
void verify_cookies(const char *url, char *result, size_t result_size) {
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        struct CookieData cookieData = {0}; // Initialiser la structure des cookies

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &cookieData);

        // Exécution de la requête
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            snprintf(result, result_size, "Erreur curl: %s", curl_easy_strerror(res));
        } else if (strlen(cookieData.data) == 0) {
            // Cookie pas trouver
            snprintf(result, result_size, "Aucun cookie trouvé sur %s", url);
        } else {
            // Cookies trouver
            snprintf(result, result_size, "Cookies trouvés sur %s:\n%s", url, cookieData.data);
        }

        // Nettoyage de cURL
        curl_easy_cleanup(curl);
    } else {
        snprintf(result, result_size, "Impossible d'initialiser cURL.");
    }
}
