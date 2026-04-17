#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

int read_file(const char* path, uint32_t* out){
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) return 0;

    uint32_t n;
    if (fread(&n, 1, sizeof(uint32_t), fp) < sizeof(uint32_t)) {
        fclose(fp);
        return 0;
    }

    *out = ntohl(n);
    fclose(fp);
    return 1;
}

int main(int argc, char *argv[]){
    uint32_t total_sum = 0;

    for (int i = 1; i < argc; i++) {
        uint32_t host_n;
        if (!read_file(argv[i], &host_n))
            return -1;

        printf("%u(0x%08x)", host_n, host_n);

        if (i < argc - 1) printf(" + ");

        total_sum += host_n;
    }

    printf(" = %u(0x%08x)\n", total_sum, total_sum);
    return 0;
}

