#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

struct header_info {
    int csp;
    int x_content_type_options;
    int x_frame_options;
    int strict_transport_security;
    int x_xss_protection;
    int referrer_policy;
    int feature_policy;
    int permissions_policy;
};

// Fix rempalcement
char *my_strndup(const char *s, size_t n) {
    size_t len = strnlen(s, n);
    char *new = (char *)malloc(len + 1);
    if (new == NULL) return NULL;
    new[len] = '\0';
    return (char *)memcpy(new, s, len);
}

// Rechercher des sous-chaines insensibles à la casse
char* case_insensitive_strstr(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; ++i) {
        for (size_t j = 0; j < needle_len && tolower(haystack[i + j]) == tolower(needle[j]); ++j) {
            if (j == needle_len - 1) return (char *)(haystack + i);
        }
    }
    return NULL;
}

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t numbytes = size * nitems;
    struct header_info *hinfo = (struct header_info *)userdata;

    char *header_line = my_strndup(buffer, numbytes);
    if (!header_line) {
        return 0;
    }
    
    if (case_insensitive_strstr(header_line, "content-security-policy:") || 
        case_insensitive_strstr(header_line, "content-security-policy-report-only:")) {
        hinfo->csp = 1;
    }
    if (case_insensitive_strstr(header_line, "x-content-type-options:")) {
        hinfo->x_content_type_options = 1;
    }
    if (case_insensitive_strstr(header_line, "x-frame-options:")) {
        hinfo->x_frame_options = 1;
    }
    if (case_insensitive_strstr(header_line, "strict-transport-security:")) {
        hinfo->strict_transport_security = 1;
    }
    if (case_insensitive_strstr(header_line, "x-xss-protection:")) {
        hinfo->x_xss_protection = 1;
    }
    if (case_insensitive_strstr(header_line, "referrer-policy:")) {
        hinfo->referrer_policy = 1;
    }
    if (case_insensitive_strstr(header_line, "feature-policy:") || 
        case_insensitive_strstr(header_line, "permissions-policy:")) {
        hinfo->feature_policy = 1;
    }
    if (case_insensitive_strstr(header_line, "permissions-policy:")) {
        hinfo->permissions_policy = 1;
    }

    free(header_line);
    return numbytes;
}

void checkSecurityHeaders(const char *url, struct header_info *hinfo) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, hinfo);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() a échoué: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}
