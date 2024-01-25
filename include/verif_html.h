#ifndef VERIF_HTML_H
#define VERIF_HTML_H

#include <curl/curl.h>

struct header_info {
    int csp;
    int x_content_type_options;
    int x_frame_options;
    int strict_transport_security;
    int x_xss_protection;
    int referrer_policy;
    int feature_policy;
    int permissions_policy; // Assurez-vous que cette ligne est présente
};


char checkSecurityHeaders(const char *url, struct header_info *hinfo);

#endif // VERIF_HTML_H
