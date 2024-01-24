#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <direct.h>
#include <time.h>
#include <glib.h>
#include "include/panel.h"
#include <sqlite3.h>
#include "include/verif_whois.h"
#include "include/verif_robot.h"
#include "include/verif_html.h"
#include "include/verif_cookie.h"

GtkWidget *robot_url_entry;
GtkWidget *robot_result_view;
GtkWidget *whois_result_view;
GtkWidget *security_result_view;
GtkWidget *cookie_result_view;
GtkWidget *whois_checkbox;
GtkWidget *robot_checkbox;
GtkWidget *security_checkbox;
GtkWidget *cookie_checkbox;

char robot_txt[8192] = {0};
char whois_response[8192] = {0};
char cookie_response[8192] = {0};
char security_response[8192] = {0};
struct header_info hinfo = {0};


static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

void create_directory(const char *path) {
    if (_mkdir(path) == -1) {
        _mkdir(path);
    }
}

void get_current_datetime(char *datetime) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    snprintf(datetime, 20, "%04d-%02d-%02d_%02d-%02d-%02d",
             timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
}

void save_result(const char *folder, const char *filename, const char *content) {
    char datetime[20];
    get_current_datetime(datetime);

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s\\%s_%s.txt", folder, filename, datetime);

    FILE *file = fopen(filepath, "w");
    if (file) {
        int result = fprintf(file, "%s", content);
        if (result >= 0) {
            printf("File successfully written: %s\n", filepath);
        } else {
            perror("Error writing to file");
        }
        fclose(file);
    } else {
        perror("Error opening file for writing");
    }
}

void save_history(const char *url, const char *timestamp) {
    char history_folder[1024];
    snprintf(history_folder, sizeof(history_folder), "history");
    create_directory(history_folder);

    char history_filepath[1024];
    snprintf(history_filepath, sizeof(history_filepath), "%s\\history.txt", history_folder);

    FILE *history_file = fopen(history_filepath, "a");
    if (history_file) {
        fprintf(history_file, "URL: %s\n", url);
        fprintf(history_file, "Date et Heure: %s\n\n", timestamp);
        fclose(history_file);
    } else {
        history_file = fopen(history_filepath, "w");
        if (history_file) {
            fprintf(history_file, "URL: %s\n", url);
            fprintf(history_file, "Date et Heure: %s\n\n", timestamp);
            fclose(history_file);
        }
    }
}

void read_config(const char *config_file, gboolean *whois_checked, gboolean *robot_checked, gboolean *security_checked, gboolean *cookie_checked) {
    GKeyFile *keyfile = g_key_file_new();

    GError *error = NULL;
    g_key_file_load_from_file(keyfile, config_file, G_KEY_FILE_NONE, &error);

    if (!error) {
        *whois_checked = g_key_file_get_boolean(keyfile, "Scans", "whois_scan", NULL);
        *robot_checked = g_key_file_get_boolean(keyfile, "Scans", "robot_scan", NULL);
        *security_checked = g_key_file_get_boolean(keyfile, "Scans", "security_scan", NULL);
        *cookie_checked = g_key_file_get_boolean(keyfile, "Scans", "cookie_scan", NULL);
    } else {
        g_error_free(error);
    }

    g_key_file_free(keyfile);
}

void configure_checkboxes(GtkWidget *whois_checkbox, GtkWidget *robot_checkbox, GtkWidget *security_checkbox, GtkWidget *cookie_checkbox) {
    gboolean whois_checked = FALSE;
    gboolean robot_checked = FALSE;
    gboolean security_checked = FALSE;
    gboolean cookie_checked = FALSE;

    read_config("config.ini", &whois_checked, &robot_checked, &security_checked, &cookie_checked);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(whois_checkbox), whois_checked);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(robot_checkbox), robot_checked);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(security_checkbox), security_checked);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cookie_checkbox), cookie_checked);
}


void perform_scan(GtkWidget *widget, gpointer data) {
    const char *url = gtk_entry_get_text(GTK_ENTRY(robot_url_entry));

    if (url != NULL && strcmp(url, "") != 0){

        create_directory("results");

        char folder[1024];
        snprintf(folder, sizeof(folder), "results\\%s", url);
        create_directory(folder);

        if (whois_checkbox != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(whois_checkbox))) {
            query_whois(url, whois_response, sizeof(whois_response));
            printf("%s", query_whois);
            save_result(folder, "whois", whois_response);
        }
        if (robot_checkbox != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(robot_checkbox))) {
            robot_query_robot_txt(url, robot_txt, sizeof(robot_txt));
            printf("Contenu de robot_txt : \n%s\n", robot_txt);
            save_result(folder, "robot", robot_txt);
        } 
        if (security_checkbox != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(security_checkbox))) {
            checkSecurityHeaders(url, &hinfo);
            snprintf(security_response, sizeof(security_response),
                    "Résultat de sécurité pour %s\n"
                    "Content-Security-Policy: %s\n"
                    "X-Content-Type-Options: %s\n"
                    "X-Frame-Options: %s\n"
                    "Strict-Transport-Security: %s\n"
                    "X-XSS-Protection: %s\n"
                    "Referrer-Policy: %s\n"
                    "Feature-Policy: %s\n"
                    "Permissions-Policy: %s\n",
                    url,
                    hinfo.csp ? "YES" : "NO",
                    hinfo.x_content_type_options ? "YES" : "NO",
                    hinfo.x_frame_options ? "YES" : "NO",
                    hinfo.strict_transport_security ? "YES" : "NO",
                    hinfo.x_xss_protection ? "YES" : "NO",
                    hinfo.referrer_policy ? "YES" : "NO",
                    hinfo.feature_policy ? "YES" : "NO",
                    hinfo.permissions_policy ? "YES" : "NO");
            save_result(folder, "security", security_response);
        }
        if (cookie_checkbox != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cookie_checkbox))) {
            verify_cookies(url, cookie_response, sizeof(cookie_response));
            save_result(folder, "cookies", cookie_response);
        }
        // Enregistre l'historique
        char datetime[20];
        get_current_datetime(datetime);
        save_history(url, datetime);

        GtkWidget *dialog;
        dialog = gtk_message_dialog_new(GTK_WINDOW(data),
                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_MESSAGE_INFO,
                                        GTK_BUTTONS_OK,
                                        "Les résultats ont été enregistrés dans le dossier : %s", folder);
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);

        } else {
        GtkWidget *dialog;
        dialog = gtk_message_dialog_new(GTK_WINDOW(data),
                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_MESSAGE_INFO,
                                        GTK_BUTTONS_OK,
                                        "Veuillez entrez une url à rechercher.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        }
    }

void on_window_closed(GtkWidget *widget, gpointer data) {
    gtk_main_quit();
}

void show_result_dialog(GtkWidget *widget, gpointer data) {
    const char *result_text = (const char *)data;

    GtkWidget *dialog = gtk_dialog_new_with_buttons("Résultats", GTK_WINDOW(gtk_widget_get_toplevel(widget)), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_STOCK_OK, GTK_RESPONSE_NONE, NULL);
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(content_area), scroll, TRUE, TRUE, 0);
    gtk_widget_set_size_request(dialog, 900, 600);

    GtkWidget *label = gtk_label_new(result_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), label);

    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

int panel(int argc, char *argv[]) {

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_name(window, "window");
    gtk_window_set_icon_from_file(GTK_WINDOW(window), "img/ico.png", NULL);
    gtk_window_set_title(GTK_WINDOW(window), "Discovery by Callidos");
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    gtk_widget_set_size_request(window, 1200, 900);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ALWAYS);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), box);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_START);

    GtkWidget *image = gtk_image_new_from_file("img/disco2.png");
    gtk_widget_set_name(image, "image");
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file("img/disco2.png", NULL);
    GdkPixbuf *scaled_pixbuf = gdk_pixbuf_scale_simple(pixbuf, 760, gdk_pixbuf_get_height(pixbuf) * 760 / gdk_pixbuf_get_width(pixbuf), GDK_INTERP_BILINEAR);
    gtk_image_set_from_pixbuf(GTK_IMAGE(image), scaled_pixbuf);
    g_object_unref(pixbuf);
    g_object_unref(scaled_pixbuf);
    gtk_box_pack_start(GTK_BOX(box), image, TRUE, TRUE, 0);

    GtkWidget *space_label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(box), space_label, FALSE, FALSE, 5); 

    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    robot_url_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(robot_url_entry), "Vérifier une URL...");
    gtk_widget_set_name(GTK_WIDGET(robot_url_entry), "search_entry");
    gtk_box_pack_start(GTK_BOX(search_box), GTK_WIDGET(robot_url_entry), TRUE, TRUE, 0);

    GtkWidget *search_button = gtk_button_new_with_label("Rechercher");
    gtk_widget_set_name(search_button, "search-button");
    gtk_box_pack_start(GTK_BOX(search_box), search_button, FALSE, FALSE, 5);
    GtkStyleContext *button_context = gtk_widget_get_style_context(search_button);
    gtk_style_context_add_class(button_context, "custom-search-button");

    gtk_box_pack_start(GTK_BOX(box), search_box, TRUE, TRUE, 30); // espacement entre logo et barre

    whois_checkbox = gtk_check_button_new_with_label("Scan WHOIS");
    gtk_widget_set_name(whois_checkbox, "common-checkbox");
    robot_checkbox = gtk_check_button_new_with_label("Scan Robots.txt");
    gtk_widget_set_name(robot_checkbox, "common-checkbox");
    security_checkbox = gtk_check_button_new_with_label("Scan des Headers HTTP");
    gtk_widget_set_name(security_checkbox, "common-checkbox");
    cookie_checkbox = gtk_check_button_new_with_label("Scan des Cookies");
    gtk_widget_set_name(cookie_checkbox, "common-checkbox");

    gtk_box_pack_start(GTK_BOX(box), whois_checkbox, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(box), robot_checkbox, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(box), security_checkbox, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(box), cookie_checkbox, FALSE, FALSE, 5);

    /////
    GtkWidget *show_whois_button = gtk_button_new_with_label("Voir WHOIS");
    GtkWidget *show_robot_button = gtk_button_new_with_label("Voir robots.txt");
    GtkWidget *show_security_button = gtk_button_new_with_label("Voir headers HTTP");
    GtkWidget *show_cookie_button = gtk_button_new_with_label("Voir les cookies");

    gtk_box_pack_start(GTK_BOX(box), show_whois_button, FALSE, FALSE, 10);
    gtk_box_pack_start(GTK_BOX(box), show_robot_button, FALSE, FALSE, 10);
    gtk_box_pack_start(GTK_BOX(box), show_security_button, FALSE, FALSE, 10);
    gtk_box_pack_start(GTK_BOX(box), show_cookie_button, FALSE, FALSE, 10);
    //////


    GtkWidget *grid = gtk_grid_new();
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);

    GtkWidget *left_label = gtk_label_new("© Callidos GROUP");
    gtk_widget_set_name(left_label, "left-label");
    gtk_grid_attach(GTK_GRID(grid), left_label, 0, 1, 1, 1);

    GtkWidget *right_label = gtk_label_new("Version 1.0.0");
    gtk_widget_set_name(right_label, "right-label");
    gtk_grid_attach(GTK_GRID(grid), right_label, 1, 1, 1, 1);


    // Positionne la grille au coin inférieur gauche de la fenêtre
    gtk_widget_set_halign(grid, GTK_ALIGN_START);
    gtk_widget_set_valign(grid, GTK_ALIGN_END);

    GtkCssProvider *css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css_provider, "src/style.css", NULL);

    GtkStyleContext *style_context = gtk_widget_get_style_context(window);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(left_label);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(right_label);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(image);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(GTK_WIDGET(robot_url_entry));
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(search_button);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(whois_checkbox);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(robot_checkbox);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(security_checkbox);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    style_context = gtk_widget_get_style_context(cookie_checkbox);
    gtk_style_context_add_provider(style_context, GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    g_signal_connect(search_button, "clicked", G_CALLBACK(perform_scan), window);
    g_signal_connect(window, "destroy", G_CALLBACK(on_window_closed), NULL);
    g_signal_connect(show_whois_button, "clicked", G_CALLBACK(show_result_dialog), whois_response);
    g_signal_connect(show_robot_button, "clicked", G_CALLBACK(show_result_dialog), robot_txt);
    g_signal_connect(show_security_button, "clicked", G_CALLBACK(show_result_dialog), security_response);
    g_signal_connect(show_cookie_button, "clicked", G_CALLBACK(show_result_dialog), cookie_response);

    gtk_widget_show_all(window);

    gtk_main();

    return 0;
}