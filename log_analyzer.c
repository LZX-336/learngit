#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE_LEN 2048
#define MAX_IPS 1024
#define IP_LEN 64

typedef struct {
    char ip[IP_LEN];
    int total;
    int failed_login;
    int sql_injection;
    int xss;
    int port_scan;
    int suspicious_ua;
} IpStats;

typedef struct {
    int lines;
    int malformed;
    int failed_login;
    int sql_injection;
    int xss;
    int port_scan;
    int suspicious_ua;
} Summary;

static int contains_ci(const char *haystack, const char *needle) {
    size_t nh = strlen(haystack);
    size_t nn = strlen(needle);
    if (nn == 0 || nh < nn) return 0;

    for (size_t i = 0; i <= nh - nn; i++) {
        size_t j = 0;
        while (j < nn) {
            char a = (char)tolower((unsigned char)haystack[i + j]);
            char b = (char)tolower((unsigned char)needle[j]);
            if (a != b) break;
            j++;
        }
        if (j == nn) return 1;
    }
    return 0;
}

static int is_ip_char(char c) {
    return isdigit((unsigned char)c) || c == '.' || c == ':';
}

static int extract_ip(const char *line, char *out_ip, size_t out_len) {
    size_t n = strlen(line);
    for (size_t i = 0; i < n; i++) {
        if (!isdigit((unsigned char)line[i])) continue;

        size_t j = i;
        while (j < n && is_ip_char(line[j])) j++;
        size_t len = j - i;

        if (len >= 7 && len < out_len) {
            int dots = 0;
            for (size_t k = i; k < j; k++) {
                if (line[k] == '.') dots++;
            }
            if (dots >= 3) {
                memcpy(out_ip, line + i, len);
                out_ip[len] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

static int classify_line(const char *line, Summary *summary, IpStats *ip_stat) {
    int marked = 0;

    if (contains_ci(line, "failed password") ||
        contains_ci(line, "authentication failure") ||
        contains_ci(line, "login failed")) {
        summary->failed_login++;
        ip_stat->failed_login++;
        marked = 1;
    }

    if (contains_ci(line, "union select") ||
        contains_ci(line, "union%20select") ||
        contains_ci(line, "or 1=1") ||
        contains_ci(line, "sleep(") ||
        contains_ci(line, "information_schema")) {
        summary->sql_injection++;
        ip_stat->sql_injection++;
        marked = 1;
    }

    if (contains_ci(line, "<script") ||
        contains_ci(line, "javascript:") ||
        contains_ci(line, "onerror=")) {
        summary->xss++;
        ip_stat->xss++;
        marked = 1;
    }

    if (contains_ci(line, "nmap") ||
        contains_ci(line, "masscan") ||
        contains_ci(line, "port scan") ||
        contains_ci(line, "syn scan")) {
        summary->port_scan++;
        ip_stat->port_scan++;
        marked = 1;
    }

    if (contains_ci(line, "sqlmap") ||
        contains_ci(line, "nikto") ||
        contains_ci(line, "acunetix")) {
        summary->suspicious_ua++;
        ip_stat->suspicious_ua++;
        marked = 1;
    }

    return marked;
}

static IpStats *get_or_create_ip_stats(IpStats *stats, int *count, const char *ip) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(stats[i].ip, ip) == 0) return &stats[i];
    }

    if (*count >= MAX_IPS) return NULL;

    IpStats *entry = &stats[*count];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
    (*count)++;
    return entry;
}

static void print_report(const Summary *s, const IpStats *ips, int ip_count) {
    printf("=== Security Log Analysis Report ===\n");
    printf("Total lines:              %d\n", s->lines);
    printf("Malformed lines:          %d\n", s->malformed);
    printf("Failed login events:      %d\n", s->failed_login);
    printf("SQL injection indicators: %d\n", s->sql_injection);
    printf("XSS indicators:           %d\n", s->xss);
    printf("Port scan indicators:     %d\n", s->port_scan);
    printf("Suspicious scanners:      %d\n", s->suspicious_ua);

    printf("\n--- Top suspicious IPs ---\n");
    printf("%-20s %-5s %-5s %-5s %-5s %-5s %-5s\n", "IP", "Tot", "Fail", "SQLi", "XSS", "Scan", "UA");
    for (int i = 0; i < ip_count; i++) {
        if (ips[i].failed_login + ips[i].sql_injection + ips[i].xss + ips[i].port_scan + ips[i].suspicious_ua == 0) {
            continue;
        }
        printf("%-20s %-5d %-5d %-5d %-5d %-5d %-5d\n",
               ips[i].ip,
               ips[i].total,
               ips[i].failed_login,
               ips[i].sql_injection,
               ips[i].xss,
               ips[i].port_scan,
               ips[i].suspicious_ua);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <log_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Failed to open log file");
        return 1;
    }

    Summary summary;
    memset(&summary, 0, sizeof(summary));

    IpStats ip_stats[MAX_IPS];
    memset(ip_stats, 0, sizeof(ip_stats));
    int ip_count = 0;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        summary.lines++;

        char ip[IP_LEN] = "unknown";
        if (!extract_ip(line, ip, sizeof(ip))) {
            summary.malformed++;
        }

        IpStats *entry = get_or_create_ip_stats(ip_stats, &ip_count, ip);
        if (!entry) {
            fprintf(stderr, "IP table overflow (max %d).\n", MAX_IPS);
            fclose(fp);
            return 1;
        }

        entry->total++;
        classify_line(line, &summary, entry);
    }

    fclose(fp);
    print_report(&summary, ip_stats, ip_count);
    return 0;
}
