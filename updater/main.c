#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <minizip/unzip.h>
#include <string.h>
#include <windows.h>

#define URL "http://uss-mtf.ddns.net/last.txt"
#define MAJ_URL "http://uss-mtf.ddns.net/maj/maj.zip"
#define VERSION_FILE "version.txt"
#define ZIP_FILE "maj.zip"

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    FILE *fp = (FILE *)userp;
    fwrite(contents, size, nmemb, fp);
    return realsize;
}

void download_files(const char *url, const char *outputFile) {
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);

        FILE *output = fopen(outputFile, "wb");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, output);

        CURLcode res = curl_easy_perform(curl);

        fclose(output);

        if (res != CURLE_OK) {
            fprintf(stderr, "Erreur lors du téléchargement : %s\n", curl_easy_strerror(res));
        } else {
            printf("Fichier téléchargé avec succès.\n");
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

void unzip(const char *zipPath) {
    unzFile zip = unzOpen(zipPath);
    if (zip == NULL) {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier ZIP.\n");
        return;
    }

    if (unzGoToFirstFile(zip) != UNZ_OK) {
        fprintf(stderr, "Erreur lors de la navigation vers le premier fichier du ZIP.\n");
        unzClose(zip);
        return;
    }

    do {
        char filename[256];
        unz_file_info fileInfo;
        if (unzGetCurrentFileInfo(zip, &fileInfo, filename, sizeof(filename), NULL, 0, NULL, 0) == UNZ_OK) {
            if (unzOpenCurrentFile(zip) == UNZ_OK) {
                char destPath[256];
                snprintf(destPath, sizeof(destPath), "../%s", filename);

                FILE *destFile = fopen(destPath, "wb");
                if (destFile != NULL) {
                    int bytesRead;
                    char buffer[8192];
                    do {
                        bytesRead = unzReadCurrentFile(zip, buffer, sizeof(buffer));
                        if (bytesRead > 0) {
                            fwrite(buffer, 1, bytesRead, destFile);
                        }
                    } while (bytesRead > 0);

                    fclose(destFile);
                } else {
                    fprintf(stderr, "Erreur lors de l'ouverture du fichier de destination (%s) : %s\n", destPath, strerror(errno));
                }

                unzCloseCurrentFile(zip);
            } else {
                fprintf(stderr, "Erreur lors de l'ouverture du fichier dans le ZIP : %s\n", filename);
            }
        } else {
            fprintf(stderr, "Erreur lors de la récupération des informations sur le fichier ZIP.\n");
        }
    } while (unzGoToNextFile(zip) == UNZ_OK);

    unzClose(zip);
}

int main() {
    const char *discovery = "\"discovery.exe\"";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, URL);

        FILE *versionFile = fopen(VERSION_FILE, "wb");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, versionFile);

        CURLcode res = curl_easy_perform(curl);

        fclose(versionFile);

        if (res != CURLE_OK) {
            fprintf(stderr, "Erreur lors du téléchargement de la version : %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        } else {
            printf("Version téléchargée avec succès.\n");
            const char *currentVersion = "1.2.0"; // VERSION LOCALE
            char downloadedVersion[100];

            FILE *versionFile = fopen(VERSION_FILE, "rb");

            fgets(downloadedVersion, sizeof(downloadedVersion), versionFile);
            fclose(versionFile);

            if (strncmp(currentVersion, downloadedVersion, strlen(currentVersion)) != 0) {
                printf("Une nouvelle version est disponible.\n");
                system("taskkill /F /IM discovery.exe"); // STOP DISCOVERY
                download_files(MAJ_URL, ZIP_FILE);
                unzip(ZIP_FILE);

                // START DISCOVERY
                STARTUPINFO si;
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);

                // Créer une structure PROCESS_INFORMATION
                PROCESS_INFORMATION pi;
                ZeroMemory(&pi, sizeof(pi));

                if (CreateProcessA(NULL, (LPSTR)discovery, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, INFINITE);

                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    printf("Erreur lors du lancement de discovery.exe.\n");
                }
            } else {
                printf("La version actuelle est à jour.\n");
            }
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return 0;
}
