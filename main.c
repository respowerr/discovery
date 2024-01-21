#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf-animation.h>

static void destroy(GtkWidget *widget, gpointer data) {
    gtk_main_quit();
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Discovery - Loading");
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 300);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ALWAYS);
    g_signal_connect(window, "destroy", G_CALLBACK(destroy), NULL);
    

    GError *error = NULL;
    GdkPixbufAnimation *animation = gdk_pixbuf_animation_new_from_file("intro.gif", &error);

    if (error != NULL) {
        g_printerr("Erreur lors du chargement de l'animation GIF : %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    GtkWidget *image = gtk_image_new_from_animation(animation);

    gtk_container_add(GTK_CONTAINER(window), image);

    gtk_widget_show_all(window);

    gtk_main();

    g_object_unref(animation);

    return 0;
}