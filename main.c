// main.c

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf-animation.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <glib.h>
#include <glib/gprintf.h>
#include "include/panel.h"

static GtkWidget *main_window;

static void destroy(GtkWidget *widget, gpointer data) {
    gtk_main_quit();
}

static gboolean show_panel_callback(gpointer data) {
    gtk_widget_destroy(main_window);

    panel(0, NULL);

    return FALSE;
}

int read_secret_code() {
    GKeyFile *keyfile;
    GError *error = NULL;

    keyfile = g_key_file_new();

    if (!g_key_file_load_from_file(keyfile, "config.ini", G_KEY_FILE_NONE, &error)) {
        g_error("Error reading config.ini file: %s", error->message);
        g_error_free(error);
        g_key_file_free(keyfile);
        return -1;
    }

    int secret_code = g_key_file_get_integer(keyfile, "SectionName", "secret_code", NULL);

    g_key_file_free(keyfile);

    return secret_code;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_icon_from_file(GTK_WINDOW(main_window), "img/ico_white.png", NULL);
    gtk_window_set_title(GTK_WINDOW(main_window), "Discovery - Loading");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 300, 300);
    gtk_window_set_position(GTK_WINDOW(main_window), GTK_WIN_POS_CENTER_ALWAYS);
    gtk_window_set_decorated(GTK_WINDOW(main_window), FALSE);
    g_signal_connect(main_window, "destroy", G_CALLBACK(destroy), NULL);

    int secret_code = read_secret_code();
    const char *image_path = (secret_code == 1) ? "img/superbug.gif" : "img/intro.gif";

    GError *error = NULL;
    GdkPixbufAnimation *animation = gdk_pixbuf_animation_new_from_file(image_path, &error);
    GtkWidget *image = gtk_image_new_from_animation(animation);
    gtk_container_add(GTK_CONTAINER(main_window), image);

    gtk_widget_show_all(main_window);

    g_object_unref(animation);

    g_timeout_add_seconds(5, show_panel_callback, NULL); // Affichage du panel & supr du main

    gtk_main();

    return 0;
}
