#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/uio.h>

#define BYTES_TO_READ 1024

static int hex_to_byte(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

static size_t get_pattern_len(char *pattern, uint8_t *pattern_bytes, int *pattern_mask) {
    size_t pattern_len = 0;

    char *p = pattern;

    while (*p != '\0') {
        while (*p == ' ') {
            p++;
        }

        if (*p == '?' && *(p + 1) == '?') {
            pattern_bytes[pattern_len] = 0;
            pattern_mask[pattern_len] = 1;
        } else if (*p == '?' && *(p + 1) == ' ') {
            pattern_bytes[pattern_len] = 0;
            pattern_mask[pattern_len] = 1;
        } else {
            int high_nibble = hex_to_byte(*p);
            int low_nibble = hex_to_byte(*(p + 1));

            pattern_bytes[pattern_len] = (uint8_t)((high_nibble << 4) | low_nibble);
            pattern_mask[pattern_len] = 0;
        }

        p += 2;
        pattern_len++;
    }

    return pattern_len;
}

unsigned long long sig_scan(char* pattern, char *target_module, pid_t pid) {
    size_t pattern_len;

    uint8_t pattern_bytes[128];
    int pattern_mask[128];

    char maps_path[128];
    char line[1024];

    unsigned char read_buff[BYTES_TO_READ];

    pattern_len = get_pattern_len(pattern, pattern_bytes, pattern_mask);

    snprintf(maps_path, 128, "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");

    while(fgets(line, sizeof(line), maps_file) != NULL) {
        unsigned long long start_addr, end_addr;
        char perms[5];

        sscanf(line, "%llx-%llx %4s %*s", &start_addr, &end_addr, perms);

        if (perms[0] != 'r') {
            continue;
        }

        if (target_module != NULL) {
            if (strstr(line, target_module) == NULL) {
                continue;
            }
        }

        for (unsigned long long i = start_addr; i < end_addr; i += BYTES_TO_READ) {
            struct iovec local_iov = { 
                .iov_base = read_buff, 
                .iov_len = BYTES_TO_READ 
            };

            struct iovec remote_iov = {  
                .iov_base = (void *)i,
                .iov_len = BYTES_TO_READ
            };

            ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

            if (bytes_read == -1) {
                continue;
            }

            for (ssize_t j = 0; j <= bytes_read; ++j) {
                int match = 1;

                for (size_t k = 0; k < pattern_len; ++k) {
                    if (!pattern_mask[k] && read_buff[j + k] != pattern_bytes[k]) {
                        match = 0;
                        break;
                    }
                }

                if (match) {
                    unsigned long long found_value = i + j;
                    fclose(maps_file);
                    return found_value;
                }
            }
        }
    }

    fclose(maps_file);

    return -1;
}
