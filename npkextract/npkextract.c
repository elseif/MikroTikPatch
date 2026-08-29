#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

typedef struct {
    const unsigned char *source;
    size_t source_len;
    size_t tag;
    unsigned int bitcount;
    unsigned char *dest;
    size_t dest_len;
    size_t dest_cap;
} TINF_DATA;

typedef struct {
    unsigned short table[16];
    unsigned short trans[288];
} TINF_TREE;

static const unsigned char tinf_default_length_bits[30] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 127
};

static const unsigned short tinf_default_length_base[30] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0
};

static const unsigned char tinf_default_dist_bits[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

static const unsigned short tinf_default_dist_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};

static const unsigned char tinf_clcidx[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

static unsigned int tinf_getbit(TINF_DATA *d) {
    if (!d->bitcount--) {
        d->tag = d->source_len ? *d->source++ : 0;
        if (d->source_len) d->source_len--;
        d->bitcount = 7;
    }
    unsigned int bit = d->tag & 1;
    d->tag >>= 1;
    return bit;
}

static unsigned int tinf_read_bits(TINF_DATA *d, int num, int base) {
    unsigned int val = 0;
    if (num) {
        unsigned int limit = 1 << num;
        unsigned int mask;
        for (mask = 1; mask < limit; mask <<= 1) {
            if (tinf_getbit(d)) val += mask;
        }
    }
    return val + base;
}

static void tinf_build_tree(TINF_TREE *t, const unsigned char *lengths, unsigned int num) {
    unsigned short offs[16];
    unsigned int i, sum = 0;

    for (i = 0; i < 16; ++i) t->table[i] = 0;
    for (i = 0; i < num; ++i) t->table[lengths[i]]++;
    t->table[0] = 0;

    for (i = 0; i < 16; ++i) {
        offs[i] = sum;
        sum += t->table[i];
    }

    for (i = 0; i < num; ++i) {
        if (lengths[i]) t->trans[offs[lengths[i]]++] = i;
    }
}

static int tinf_decode_symbol(TINF_DATA *d, const TINF_TREE *t) {
    int sum = 0, cur = 0, len = 0;
    do {
        cur = 2 * cur + tinf_getbit(d);
        len++;
        sum += t->table[len];
        cur -= t->table[len];
    } while (cur >= 0);
    return t->trans[sum + cur];
}

static void tinf_build_fixed_trees(TINF_TREE *lt, TINF_TREE *dt) {
    unsigned char lengths[288];
    int i;
    for (i = 0; i <= 143; ++i) lengths[i] = 8;
    for (; i <= 255; ++i) lengths[i] = 9;
    for (; i <= 279; ++i) lengths[i] = 7;
    for (; i <= 287; ++i) lengths[i] = 8;
    tinf_build_tree(lt, lengths, 288);
    for (i = 0; i < 32; ++i) lengths[i] = 5;
    tinf_build_tree(dt, lengths, 32);
}

static int tinf_inflate_block_data(TINF_DATA *d, TINF_TREE *lt, TINF_TREE *dt) {
    while (1) {
        int sym = tinf_decode_symbol(d, lt);
        if (sym == 256) return 0;

        if (sym < 256) {
            if (d->dest_len >= d->dest_cap) {
                size_t ncap = d->dest_cap ? d->dest_cap * 2 : 1024 * 1024;
                unsigned char *nd = realloc(d->dest, ncap);
                if (!nd) return -1;
                d->dest = nd;
                d->dest_cap = ncap;
            }
            d->dest[d->dest_len++] = (unsigned char)sym;
        } else {
            sym -= 257;
            int length = tinf_read_bits(d, tinf_default_length_bits[sym], tinf_default_length_base[sym]);
            int dist_sym = tinf_decode_symbol(d, dt);
            int dist = tinf_read_bits(d, tinf_default_dist_bits[dist_sym], tinf_default_dist_base[dist_sym]);

            if (d->dest_len + length > d->dest_cap) {
                size_t ncap = (d->dest_len + length) * 2 + 1024 * 1024;
                unsigned char *nd = realloc(d->dest, ncap);
                if (!nd) return -1;
                d->dest = nd;
                d->dest_cap = ncap;
            }

            unsigned char *src = d->dest + d->dest_len - dist;
            while (length--) {
                d->dest[d->dest_len++] = *src++;
            }
        }
    }
}

static int tinf_inflate_uncompressed_block(TINF_DATA *d) {
    d->bitcount = 0;
    if (d->source_len < 4) return -1;
    unsigned int length = d->source[0] | (d->source[1] << 8);
    d->source += 4;
    d->source_len -= 4;
    if (d->source_len < length) return -1;

    if (d->dest_len + length > d->dest_cap) {
        size_t ncap = d->dest_len + length + 1024 * 1024;
        unsigned char *nd = realloc(d->dest, ncap);
        if (!nd) return -1;
        d->dest = nd;
        d->dest_cap = ncap;
    }

    memcpy(d->dest + d->dest_len, d->source, length);
    d->dest_len += length;
    d->source += length;
    d->source_len -= length;
    return 0;
}

static int tinf_inflate_dynamic_block(TINF_DATA *d) {
    TINF_TREE lt, dt, ct;
    unsigned char lengths[288 + 32];
    unsigned int hlit = tinf_read_bits(d, 5, 257);
    unsigned int hdist = tinf_read_bits(d, 5, 1);
    unsigned int hclen = tinf_read_bits(d, 4, 4);
    unsigned int i, num;

    unsigned char clen[19];
    memset(clen, 0, sizeof(clen));
    for (i = 0; i < hclen; ++i) clen[tinf_clcidx[i]] = tinf_read_bits(d, 3, 0);
    tinf_build_tree(&ct, clen, 19);

    for (num = 0; num < hlit + hdist;) {
        int sym = tinf_decode_symbol(d, &ct);
        if (sym < 16) {
            lengths[num++] = sym;
        } else if (sym == 16) {
            unsigned char prev = lengths[num - 1];
            for (i = tinf_read_bits(d, 2, 3); i; --i) lengths[num++] = prev;
        } else if (sym == 17) {
            for (i = tinf_read_bits(d, 3, 3); i; --i) lengths[num++] = 0;
        } else {
            for (i = tinf_read_bits(d, 7, 11); i; --i) lengths[num++] = 0;
        }
    }

    tinf_build_tree(&lt, lengths, hlit);
    tinf_build_tree(&dt, lengths + hlit, hdist);
    return tinf_inflate_block_data(d, &lt, &dt);
}

static unsigned char *zlib_decompress(const unsigned char *src, size_t src_len, size_t *out_len) {
    if (src_len < 2) return NULL;
    size_t offset = 0;
    // Check zlib header (RFC 1950)
    if ((src[0] * 256 + src[1]) % 31 == 0 && (src[0] & 0x0F) == 8) {
        offset = 2;
        if (src[1] & 0x20) offset += 4;
    }

    TINF_DATA d;
    memset(&d, 0, sizeof(d));
    d.source = src + offset;
    d.source_len = src_len > offset ? src_len - offset : 0;
    d.dest_cap = src_len * 4 + 1024 * 1024;
    d.dest = malloc(d.dest_cap);
    if (!d.dest) return NULL;

    int bfinal;
    do {
        bfinal = tinf_getbit(&d);
        int btype = tinf_read_bits(&d, 2, 0);

        if (btype == 0) {
            if (tinf_inflate_uncompressed_block(&d) < 0) { free(d.dest); return NULL; }
        } else if (btype == 1) {
            TINF_TREE lt, dt;
            tinf_build_fixed_trees(&lt, &dt);
            if (tinf_inflate_block_data(&d, &lt, &dt) < 0) { free(d.dest); return NULL; }
        } else if (btype == 2) {
            if (tinf_inflate_dynamic_block(&d) < 0) { free(d.dest); return NULL; }
        } else {
            free(d.dest);
            return NULL;
        }
    } while (!bfinal);

    *out_len = d.dest_len;
    return d.dest;
}

static void mkdir_p(const char *dir) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

const char *get_part_name(uint32_t id) {
    switch (id) {
        case 0x01: return "NAME_INFO";
        case 0x02: return "DESCRIPTION";
        case 0x03: return "DEPENDENCIES";
        case 0x04: return "FILE_CONTAINER";
        case 0x07: return "INSTALL_SCRIPT";
        case 0x08: return "UNINSTALL_SCRIPT";
        case 0x09: return "SIGNATURE";
        case 0x10: return "ARCHITECTURE";
        case 0x11: return "PKG_CONFLICTS";
        case 0x12: return "PKG_INFO";
        case 0x13: return "FEATURES";
        case 0x14: return "PKG_FEATURES";
        case 0x15: return "SQUASHFS";
        case 0x16: return "NULL_BLOCK";
        case 0x17: return "GIT_COMMIT";
        case 0x18: return "CHANNEL";
        case 0x19: return "HEADER";
        default:   return "UNKNOWN";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <package.npk> <output_directory>\n", argv[0]);
        return 1;
    }

    const char *npk_path = argv[1];
    const char *out_dir = argv[2];

    FILE *fp = fopen(npk_path, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open NPK file '%s'\n", npk_path);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("Parsing NPK: '%s' (%ld bytes)\n", npk_path, file_size);
    mkdir_p(out_dir);

    int total_extracted = 0;
    long offset = 0;

    while (offset + 6 <= file_size) {
        fseek(fp, offset, SEEK_SET);
        uint16_t id16;
        uint32_t size32;

        if (fread(&id16, 2, 1, fp) != 1 || fread(&size32, 4, 1, fp) != 1) {
            break;
        }

        if (id16 > 0 && id16 <= 0x20 && size32 <= (uint32_t)(file_size - offset - 6)) {
            printf("  [Part 0x%02X: %-15s] offset=%ld, size=%u\n", id16, get_part_name(id16), offset, size32);

            if (id16 == 0x04) { // FILE_CONTAINER
                unsigned char *zbuf = malloc(size32);
                if (zbuf && fread(zbuf, 1, size32, fp) == size32) {
                    size_t decomp_len = 0;
                    unsigned char *decomp = zlib_decompress(zbuf, size32, &decomp_len);
                    if (decomp) {
                        printf("    -> Decompressed FILE_CONTAINER: %zu bytes\n", decomp_len);

                        unsigned char *p = decomp;
                        unsigned char *end = decomp + decomp_len;
                        int item_idx = 0;

                        while (p + 30 <= end) {
                            uint32_t fmode     = *(uint32_t *)(p + 0);
                            uint32_t fmtime    = *(uint32_t *)(p + 8);
                            uint32_t fsize     = *(uint32_t *)(p + 24);
                            uint16_t name_len  = *(uint16_t *)(p + 28);
                            p += 30;

                            if (p + name_len > end) {
                                printf("    -> Header overrun: name_len=%u exceeds buffer\n", name_len);
                                break;
                            }

                            char fname[512] = {0};
                            if (name_len >= sizeof(fname)) name_len = sizeof(fname) - 1;
                            memcpy(fname, p, name_len);
                            fname[name_len] = '\0';
                            p += name_len;

                            if (p + fsize > end) {
                                printf("    -> Data overrun: '%s' size=%u exceeds buffer\n", fname, fsize);
                                break;
                            }

                            char full_path[1024];
                            snprintf(full_path, sizeof(full_path), "%s/%s", out_dir, fname);

                            char dir_path[1024];
                            snprintf(dir_path, sizeof(dir_path), "%s", full_path);
                            char *slash = strrchr(dir_path, '/');
                            if (slash) { *slash = '\0'; mkdir_p(dir_path); }

                            if (S_ISDIR(fmode)) {
                                mkdir_p(full_path);
                                printf("    -> [%d] [DIR]  %s/\n", ++item_idx, fname);
                            } else if (S_ISLNK(fmode)) {
                                char target[1024] = {0};
                                size_t tlen = fsize < sizeof(target) ? fsize : sizeof(target) - 1;
                                memcpy(target, p, tlen);
                                unlink(full_path);
                                symlink(target, full_path);
                                printf("    -> [%d] [LINK] %s -> %s\n", ++item_idx, fname, target);
                                total_extracted++;
                            } else {
                                FILE *out = fopen(full_path, "wb");
                                if (out) {
                                    fwrite(p, 1, fsize, out);
                                    fclose(out);
                                    chmod(full_path, fmode ? (fmode & 07777) : 0644);

                                    if (fmtime) {
                                        struct utimbuf ut;
                                        ut.actime = fmtime;
                                        ut.modtime = fmtime;
                                        utime(full_path, &ut);
                                    }

                                    printf("    -> [%d] [FILE] %s (%u bytes, mode=%04o)\n", ++item_idx, fname, fsize, fmode & 07777);
                                    total_extracted++;
                                } else {
                                    fprintf(stderr, "Warning: Failed to create file '%s'\n", full_path);
                                }
                            }

                            p += fsize;
                        }

                        free(decomp);
                    } else {
                        printf("    -> ZLIB decompression failed for FILE_CONTAINER\n");
                    }
                }
                if (zbuf) free(zbuf);
            } else if (id16 == 0x15) { 
                char sq_file[1024];
                snprintf(sq_file, sizeof(sq_file), "%s/image.squashfs", out_dir);
                FILE *out = fopen(sq_file, "wb");
                if (out) {
                    unsigned char buf[65536];
                    uint32_t remaining = size32;
                    while (remaining > 0) {
                        size_t to_read = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                        size_t n = fread(buf, 1, to_read, fp);
                        if (n == 0) break;
                        fwrite(buf, 1, n, out);
                        remaining -= n;
                    }
                    fclose(out);
                    printf("    -> Extracted SQUASHFS image: %s (%u bytes)\n", sq_file, size32);
                    total_extracted++;
                }
            }

            offset += 6 + size32;
            continue;
        }

        offset++;
    }

    fclose(fp);
    printf("\nExtraction complete: %d item(s) extracted from NPK to '%s'.\n", total_extracted, out_dir);
    return 0;
}
