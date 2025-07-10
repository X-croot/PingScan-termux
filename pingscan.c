#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_THREADS 100
#define PROGRESS_BAR_WIDTH 50

#define COLOR_GREEN "\033[0;32m"
#define COLOR_RESET "\033[0m"

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[32];
    char os[64];
    char vendor[128];
    int is_self;
} Result;

char** ip_list = NULL;
Result* reachable_list = NULL;
int ip_count = 0;
int completed_count = 0;
int reachable_count = 0;
int done = 0;

char own_ip[INET_ADDRSTRLEN];
char own_mac[32];

pthread_mutex_t print_mutex;
FILE* output = NULL;

uint32_t ip_to_int(const char* ip_str) {
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_str, &ip_addr);
    return ntohl(ip_addr.s_addr);
}

void int_to_ip(uint32_t ip, char* buffer) {
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
}

void get_mac_address(const char* ip, char* mac_buffer) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "arp -n %s 2>/dev/null", ip);
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        mac_buffer[0] = '\0';
        return;
    }

    char line[256];
    mac_buffer[0] = '\0';
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, ip)) {
            char* token = strtok(line, " \t");
            while (token != NULL) {
                if (strchr(token, ':') && strlen(token) >= 8) {
                    strncpy(mac_buffer, token, 31);
                    mac_buffer[31] = '\0';
                    break;
                }
                token = strtok(NULL, " \t");
            }
        }
    }
    pclose(fp);
}

void detect_os(const char* ip, char* os_buffer) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s", ip);
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        strcpy(os_buffer, "Unknown");
        return;
    }

    char line[256];
    os_buffer[0] = '\0';
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "ttl=")) {
            char* ttl_str = strstr(line, "ttl=");
            int ttl = atoi(ttl_str + 4);
            if (ttl >= 0 && ttl <= 64)
                strcpy(os_buffer, "Linux/macOS/Android");
            else if (ttl > 64 && ttl <= 128)
                strcpy(os_buffer, "Windows");
            else
                strcpy(os_buffer, "Unknown");
            break;
        }
    }
    if (os_buffer[0] == '\0') {
        strcpy(os_buffer, "Unknown");
    }
    pclose(fp);
}

void get_vendor_from_mac(const char* mac, char* vendor_buffer, size_t size) {
    FILE* fp = fopen("oui.txt", "r");
    if (!fp) {
        snprintf(vendor_buffer, size, "Unknown Vendor");
        return;
    }

    char mac_prefix[7] = {0};
    int j = 0;
    for (int i = 0; mac[i] != '\0' && j < 6; i++) {
        if (mac[i] != ':') {
            mac_prefix[j++] = toupper(mac[i]);
        }
    }
    mac_prefix[6] = '\0';

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; i < 6; i++) {
            line[i] = toupper(line[i]);
        }
        if (strncmp(line, mac_prefix, 6) == 0) {
            char* vendor = line + 6;
            while (*vendor == '\t' || *vendor == ' ') vendor++;
            vendor[strcspn(vendor, "\r\n")] = 0;
            strncpy(vendor_buffer, vendor, size - 1);
            vendor_buffer[size - 1] = '\0';
            fclose(fp);
            return;
        }
    }

    fclose(fp);
    snprintf(vendor_buffer, size, "Unknown Vendor");
}

void* progress_bar_thread(void* arg) {
    while (!done) {
        pthread_mutex_lock(&print_mutex);
        float percent = (float)completed_count / ip_count;
        int filled = (int)(percent * PROGRESS_BAR_WIDTH);

        printf("\r[");
        for (int i = 0; i < PROGRESS_BAR_WIDTH; i++) {
            printf(i < filled ? "#" : " ");
        }
        printf("] %3.0f%% | %d/%d completed | %d remaining", percent * 100, completed_count, ip_count, ip_count - completed_count);
        fflush(stdout);
        pthread_mutex_unlock(&print_mutex);
        usleep(200000);
    }
    return NULL;
}

void* ping_ip(void* arg) {
    char* ip = (char*)arg;
    char command[128];
    snprintf(command, sizeof(command), "ping -c 1 -W 1 %s > /dev/null 2>&1", ip);
    int result = system(command);

    pthread_mutex_lock(&print_mutex);
    if (result == 0) {
        reachable_list = realloc(reachable_list, (reachable_count + 1) * sizeof(Result));
        strncpy(reachable_list[reachable_count].ip, ip, INET_ADDRSTRLEN);
        reachable_list[reachable_count].ip[INET_ADDRSTRLEN - 1] = '\0';
        reachable_list[reachable_count].is_self = (strcmp(ip, own_ip) == 0);

        if (reachable_list[reachable_count].is_self) {
            strncpy(reachable_list[reachable_count].mac, own_mac, 31);
            reachable_list[reachable_count].mac[31] = '\0';
            strcpy(reachable_list[reachable_count].os, "<- This is your device");
            strcpy(reachable_list[reachable_count].vendor, "");
        } else {
            get_mac_address(ip, reachable_list[reachable_count].mac);
            detect_os(ip, reachable_list[reachable_count].os);
            if (strlen(reachable_list[reachable_count].mac) > 0) {
                get_vendor_from_mac(reachable_list[reachable_count].mac, reachable_list[reachable_count].vendor, sizeof(reachable_list[reachable_count].vendor));
            } else {
                strcpy(reachable_list[reachable_count].vendor, "Unknown Vendor");
            }
        }

        reachable_count++;
    }
    completed_count++;
    pthread_mutex_unlock(&print_mutex);

    free(ip);
    return NULL;
}

void get_own_ip_mac() {
    FILE* fp = popen("hostname -I | awk '{print $1}'", "r");
    if (fp) {
        fgets(own_ip, sizeof(own_ip), fp);
        own_ip[strcspn(own_ip, "\n")] = 0;
        pclose(fp);
    } else {
        own_ip[0] = '\0';
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip neigh show %s 2>/dev/null", own_ip);
    fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        own_mac[0] = '\0';
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, own_ip)) {
                char* token = strtok(line, " \t");
                while (token != NULL) {
                    if (strchr(token, ':') && strlen(token) >= 8) {
                        strncpy(own_mac, token, 31);
                        own_mac[31] = '\0';
                        break;
                    }
                    token = strtok(NULL, " \t");
                }
            }
        }
        pclose(fp);
    } else {
        own_mac[0] = '\0';
    }
}

int main(int argc, char* argv[]) {

    printf(COLOR_GREEN
    "_____________               ________                    \n"
    "___  __ \\__(_)_____________ __  ___/___________ _______ \n"
    "__  /_/ /_  /__  __ \\_  __ `/____ \\_  ___/  __ `/_  __ \\\n"
    "_  ____/_  / _  / / /  /_/ /____/ // /__ / /_/ /_  / / /\n"
    "/_/     /_/  /_/ /_/\\__, / /____/ \\___/ \\__,_/ /_/ /_/ \n"
    "                    /____/                              \n"
    "--------------------------------------------------------\n"
    "              [+] Fast Network Scanner Tool\n"
    "                    Tool: PingScan v1.0\n"
    COLOR_RESET);

    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <start_ip> <end_ip> [-o output.txt]\n", argv[0]);
        return 1;
    }

    char* start_ip = argv[1];
    char* end_ip = argv[2];

    if (argc == 5 && strcmp(argv[3], "-o") == 0) {
        output = fopen(argv[4], "w");
        if (!output) {
            perror("Failed to open file");
            return 1;
        }
    }

    get_own_ip_mac();

    uint32_t start = ip_to_int(start_ip);
    uint32_t end = ip_to_int(end_ip);

    if (start > end) {
        fprintf(stderr, "Invalid IP range!\n");
        return 1;
    }

    for (uint32_t ip = start; ip <= end; ip++) {
        char buffer[INET_ADDRSTRLEN];
        int_to_ip(ip, buffer);
        ip_list = realloc(ip_list, (ip_count + 1) * sizeof(char*));
        ip_list[ip_count] = strdup(buffer);
        ip_count++;
    }

    printf("[*] Scanning %d IPs...\n", ip_count);
    if (output) {
        fprintf(output, "[*] Scanning %d IPs...\n", ip_count);
    }

    pthread_mutex_init(&print_mutex, NULL);

    pthread_t progress_thread;
    pthread_create(&progress_thread, NULL, progress_bar_thread, NULL);

    int i = 0;
    while (i < ip_count) {
        pthread_t threads[MAX_THREADS];
        int j;
        for (j = 0; j < MAX_THREADS && i + j < ip_count; j++) {
            pthread_create(&threads[j], NULL, ping_ip, strdup(ip_list[i + j]));
        }
        for (int k = 0; k < j; k++) {
            pthread_join(threads[k], NULL);
        }
        i += j;
    }

    done = 1;
    pthread_join(progress_thread, NULL);

    printf(COLOR_GREEN "\n\n[+] Scan complete! Reachable IPs (%d):\n" COLOR_RESET, reachable_count);
    printf("---------------------------------------------------------\n");
    if (output) {
        fprintf(output, "\n\n[+] Scan complete! Reachable IPs (%d):\n", reachable_count);
        fprintf(output, "---------------------------------------------------------\n");
    }

    for (int i = 0; i < reachable_count; i++) {
        printf("[*] %s\t[MAC] %s\t[OS] %s\t[Vendor] %s\n",
               reachable_list[i].ip,
               strlen(reachable_list[i].mac) > 0 ? reachable_list[i].mac : "(MAC unavailable)",
               reachable_list[i].os,
               strlen(reachable_list[i].vendor) > 0 ? reachable_list[i].vendor : "(Vendor unknown)");

        if (output) {
            fprintf(output, "%s\t%s\t%s\t%s\n",
                    reachable_list[i].ip,
                    strlen(reachable_list[i].mac) > 0 ? reachable_list[i].mac : "(MAC unavailable)",
                    reachable_list[i].os,
                    strlen(reachable_list[i].vendor) > 0 ? reachable_list[i].vendor : "(Vendor unknown)");
        }
    }

    for (int i = 0; i < ip_count; i++) {
        free(ip_list[i]);
    }
    free(ip_list);
    free(reachable_list);
    if (output) fclose(output);
    pthread_mutex_destroy(&print_mutex);
    return 0;
}
