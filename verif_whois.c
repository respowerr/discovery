#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "include/verif_whois.h"

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    char *data = (char *)contents;
    char *response = (char *)userp;
    strncat(response, data, real_size);
    return real_size;
}

void query_whois(const char *domain, char *response, size_t response_size) {
    CURL *curl;
    CURLcode res;
    char readBuffer[8192] = {0}; // Initialize the buffer

    curl = curl_easy_init();
    if(curl) {
        printf("URL AVANT CHAR : %s\n", domain);    
        char url[256];
        snprintf(url, sizeof(url), "https://api.ip2whois.com/v2?key=F3E9F67CFF7993AF48D3A24BDC9B566B&domain=%s", domain);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, readBuffer);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);  // DESAC SSL
        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            strncpy(response, readBuffer, response_size - 1);
            response[response_size - 1] = '\0';
        }

        curl_easy_cleanup(curl);
    }
}
