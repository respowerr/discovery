#include <curl/curl.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include "include/verif_robot.h"



size_t robot_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    char *data = (char *)contents;
    char *response = (char *)userp;
    strncat(response, data, real_size);
    return real_size;
}

bool is_valid_url(const char *url) {
    // Simple check for a valid URL format, you can improve this validation
    return strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0;
}

void prepend_http_if_needed(char *url, size_t url_size) {
    if (!is_valid_url(url)) {
        char temp_url[url_size + 8];
        snprintf(temp_url, sizeof(temp_url), "http://%s", url);
        strncpy(url, temp_url, url_size);
    }
}

void robot_extract_important_lines(const char *input, char *output, size_t output_size) {
    const char *delimiters = "\n\r";
    const char *important_keywords[] = {"User-agent:", "Disallow:", "Allow:"};

    char *line = strtok((char *)input, delimiters);
    while (line != NULL) {
        for (size_t i = 0; i < sizeof(important_keywords) / sizeof(important_keywords[0]); ++i) {
            if (strstr(line, important_keywords[i]) == line) {
                strncat(output, line, output_size - strlen(output) - 1);
                strncat(output, "\n", output_size - strlen(output) - 1);
                break;
            }
        }
        line = strtok(NULL, delimiters);
    }
}

void robot_query_robot_txt(const char *url, char *response, size_t response_size) {
    char formatted_url[256];
    strncpy(formatted_url, url, sizeof(formatted_url));
    prepend_http_if_needed(formatted_url, sizeof(formatted_url));

    CURL *curl;
    CURLcode res;
    char readBuffer[16384] = {0};
    char url_with_robots[256];
    snprintf(url_with_robots, sizeof(url_with_robots), "%s/robots.txt", formatted_url);

    // Creation repertoire 
    char directory_name[256];
    snprintf(directory_name, sizeof(directory_name), "resultat/%s", formatted_url);
    
    // Nome le repertoire
    char file_name[256];
    snprintf(file_name, sizeof(file_name), "resultat/%s/robots.txt", formatted_url);
    
    #ifdef _WIN32
        _mkdir(directory_name); // Utilisez _mkdir sous Windows
    #else
        mkdir(directory_name, 0777);
    #endif

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url_with_robots);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, robot_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, readBuffer);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // redirections

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);


        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            robot_extract_important_lines(readBuffer, response, response_size);
            
            // Ecrit reponse dans un fichier
            FILE *file = fopen(file_name, "w");
            if (file) {
                fprintf(file, "%s", response);
                fclose(file);
            } else {
                fprintf(stderr, "Failed to create/write to file\n");
            }
        }

        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize curl\n");
    }

    curl_global_cleanup();
}
