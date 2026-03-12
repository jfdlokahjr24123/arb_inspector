/*
 * extract_oem_metadata.c
 *
 * 从 ELF 文件（如 xbl_config.img）的 HASH 段中提取 OEM 元数据。
 * 编译（静态链接 musl 到 ARM64）：
 *   aarch64-linux-musl-gcc -static -o extract_oem_metadata extract_oem_metadata.c
 *
 * 用法：
 *   ./extract_oem_metadata [--debug] [--block] <xbl_config.img>
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

/* ELF64 常量 */
#define EI_MAG0         0
#define EI_MAG1         1
#define EI_MAG2         2
#define EI_MAG3         3
#define EI_CLASS        4
#define EI_DATA         5
#define ELFMAG0         0x7f
#define ELFMAG1         'E'
#define ELFMAG2         'L'
#define ELFMAG3         'F'
#define ELFCLASS64      2
#define ELFDATA2LSB     1

/* 程序头类型 */
#define PT_NULL         0

/* 扫描 HASH 段的限制 */
#define HASH_HEADER_SIZE    36          /* 固定头部大小 */
#define MAX_SCAN_OFFSET     0x1000      /* 每个段最多扫描 4KB */
#define MAX_SEGMENT_BYTES   (20ULL * 1024 * 1024)   /* 20 MB 安全上限 */

/* 字段合理范围（根据实际固件样本得出） */
#define VERSION_MIN         1
#define VERSION_MAX         1000
#define COMMON_SIZE_MAX     0x1000
#define QTI_SIZE_MAX        0x1000
#define OEM_SIZE_MAX        0x4000
#define HASH_TABLE_SIZE_MAX 0x10000     /* 64KB */
#define ARB_VALUE_MAX       127

/* 小端读取函数 */
static uint16_t read_le16(const uint8_t *buf, size_t off) {
    return (uint16_t)buf[off] |
           (uint16_t)buf[off + 1] << 8;
}

static uint32_t read_le32(const uint8_t *buf, size_t off) {
    return (uint32_t)buf[off] |
           (uint32_t)buf[off + 1] << 8 |
           (uint32_t)buf[off + 2] << 16 |
           (uint32_t)buf[off + 3] << 24;
}

static uint64_t read_le64(const uint8_t *buf, size_t off) {
    return (uint64_t)buf[off] |
           (uint64_t)buf[off + 1] << 8 |
           (uint64_t)buf[off + 2] << 16 |
           (uint64_t)buf[off + 3] << 24 |
           (uint64_t)buf[off + 4] << 32 |
           (uint64_t)buf[off + 5] << 40 |
           (uint64_t)buf[off + 6] << 48 |
           (uint64_t)buf[off + 7] << 56;
}

/* 在段数据中查找可能的 HASH 头部，返回段内偏移，失败返回 -1 */
static long find_hash_header(const uint8_t *seg, size_t seg_len,
                             uint64_t seg_off, int debug, int seg_idx) {
    size_t limit = (MAX_SCAN_OFFSET < seg_len) ? MAX_SCAN_OFFSET : seg_len;
    for (size_t off = 0; off + HASH_HEADER_SIZE <= limit; off += 4) {
        uint32_t version   = read_le32(seg, off);
        uint32_t common_sz = read_le32(seg, off + 4);
        uint32_t qti_sz    = read_le32(seg, off + 8);
        uint32_t oem_sz    = read_le32(seg, off + 12);
        uint32_t hash_sz   = read_le32(seg, off + 16);

        /* 版本范围检查 */
        if (version < VERSION_MIN || version > VERSION_MAX)
            continue;

        /* 各区域大小合理性检查 */
        if (common_sz > COMMON_SIZE_MAX ||
            qti_sz    > QTI_SIZE_MAX    ||
            oem_sz    > OEM_SIZE_MAX)
            continue;

        if (hash_sz == 0 || hash_sz > HASH_TABLE_SIZE_MAX)
            continue;

        /* 确保整个描述区域不超出段范围 */
        size_t total = HASH_HEADER_SIZE + common_sz + qti_sz + oem_sz;
        if (off + total > seg_len)
            continue;

        if (debug) {
            fprintf(stderr,
                    "[DEBUG] Segment at file offset 0x%llx: possible header at +0x%zx (file 0x%llx)\n",
                    (unsigned long long)seg_off, off,
                    (unsigned long long)(seg_off + off));
        }
        return (long)off;
    }
    return -1;
}

/* OEM 元数据结构 */
typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t arb;
    uint64_t seg_off;      /* 所在段文件偏移 */
    long     header_off;    /* 段内头部偏移 */
} hash_info_t;

/* 尝试从段中提取 OEM 元数据，成功返回 1 并填充 info，否则返回 0 */
static int try_extract_hash_info(const uint8_t *seg, size_t seg_len,
                                 uint64_t seg_off, int debug, int seg_idx,
                                 hash_info_t *info) {
    long header_off = find_hash_header(seg, seg_len, seg_off, debug, seg_idx);
    if (header_off < 0)
        return 0;

    uint32_t common_sz = read_le32(seg, (size_t)header_off + 4);
    uint32_t qti_sz    = read_le32(seg, (size_t)header_off + 8);

    /* OEM 区域起始位置 */
    size_t oem_off = (size_t)header_off + HASH_HEADER_SIZE + common_sz + qti_sz;
    if (oem_off + 12 > seg_len)   /* 需要 3 个 u32 */
        return 0;

    uint32_t major = read_le32(seg, oem_off);
    uint32_t minor = read_le32(seg, oem_off + 4);
    uint32_t arb   = read_le32(seg, oem_off + 8);

    /* 合理性检查 */
    if (major > VERSION_MAX || minor > VERSION_MAX || arb > ARB_VALUE_MAX)
        return 0;

    if (debug) {
        fprintf(stderr,
                "[DEBUG]  -> OEM at +0x%zx (file 0x%llx): major=%u, minor=%u, arb=%u\n",
                oem_off, (unsigned long long)(seg_off + oem_off),
                major, minor, arb);
    }

    info->major      = major;
    info->minor      = minor;
    info->arb        = arb;
    info->seg_off    = seg_off;
    info->header_off = header_off;
    return 1;
}

/* 扫描候选段列表，返回第一个找到的 info，成功返回 1，否则 0 */
static int scan_candidates(FILE *fp,
                           const uint64_t *offsets,
                           const uint64_t *sizes,
                           const int      *indices,
                           int count,
                           int debug,
                           hash_info_t *out_info) {
    for (int i = 0; i < count; i++) {
        uint64_t off  = offsets[i];
        uint64_t size = sizes[i];
        int      idx  = indices[i];

        if (debug) {
            fprintf(stderr,
                    "[DEBUG] Scanning segment %d at file offset 0x%llx (size 0x%llx)\n",
                    idx, (unsigned long long)off, (unsigned long long)size);
        }

        /* 分配缓冲区并读取整个段 */
        uint8_t *seg = malloc((size_t)size);
        if (!seg) {
            perror("malloc");
            return -1;   /* 内存不足，直接退出 */
        }

        if (fseeko(fp, off, SEEK_SET) != 0) {
            perror("fseeko");
            free(seg);
            return -1;
        }

        size_t read_len = fread(seg, 1, (size_t)size, fp);
        if (read_len != (size_t)size) {
            if (feof(fp))
                fprintf(stderr, "Warning: segment %d: unexpected EOF (read %zu, expected %llu)\n",
                        idx, read_len, (unsigned long long)size);
            else
                perror("fread");
            free(seg);
            continue;   /* 跳过此段 */
        }

        int found = try_extract_hash_info(seg, (size_t)size, off, debug, idx, out_info);
        free(seg);

        if (found) {
            if (debug) {
                fprintf(stderr,
                        "[DEBUG] >>> SELECTED segment %d (offset 0x%llx) with header at +0x%lx\n",
                        idx, (unsigned long long)out_info->seg_off, out_info->header_off);
            }
            return 1;
        }
    }
    return 0;
}

/* 打印用法 */
static void usage(const char *progname) {
    fprintf(stderr, "Usage: %s [--debug] [--block] <xbl_config.img>\nSource: https://github.com/Dere3046/arb_inspector", progname);
}

int main(int argc, char **argv) {
    int debug = 0;
    int block_mode = 0;
    const char *filepath = NULL;

    /* 简单的手动参数解析（不使用 getopt_long 以保持兼容性） */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "--block") == 0 || strcmp(argv[i], "-b") == 0) {
            block_mode = 1;
        } else if (argv[i][0] != '-') {
            if (!filepath)
                filepath = argv[i];
            else {
                usage(argv[0]);
                return 1;
            }
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!filepath) {
        usage(argv[0]);
        return 1;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    /* 获取文件大小（仅用于非 block 模式下的检查） */
    uint64_t file_size = 0;
    if (!block_mode) {
        if (fseeko(fp, 0, SEEK_END) != 0) {
            perror("fseeko");
            fclose(fp);
            return 1;
        }
        off_t sz = ftello(fp);
        if (sz == (off_t)-1) {
            perror("ftello");
            fclose(fp);
            return 1;
        }
        file_size = (uint64_t)sz;
        rewind(fp);
    }

    /* 读取 ELF 头 (64 字节) */
    uint8_t ehdr[64];
    if (fread(ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF header\n");
        fclose(fp);
        return 1;
    }

    /* 验证 ELF 魔数 */
    if (ehdr[EI_MAG0] != ELFMAG0 || ehdr[EI_MAG1] != ELFMAG1 ||
        ehdr[EI_MAG2] != ELFMAG2 || ehdr[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not an ELF file\n");
        fclose(fp);
        return 1;
    }

    /* 检查 64 位和小端 */
    if (ehdr[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Not a 64-bit ELF file\n");
        fclose(fp);
        return 1;
    }
    if (ehdr[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "Not a little-endian ELF file\n");
        fclose(fp);
        return 1;
    }

    /* 解析程序头表信息 */
    uint64_t e_phoff   = read_le64(ehdr, 0x20);
    uint16_t e_phentsz = read_le16(ehdr, 0x36);
    uint16_t e_phnum   = read_le16(ehdr, 0x38);

    if (e_phentsz < 56 || e_phnum == 0) {
        fprintf(stderr, "Invalid program header table\n");
        fclose(fp);
        return 1;
    }

    /* 存储候选段（类型0和其他类型） */
    /* 由于最大段数量未知，使用动态数组（简单起见，固定上限 128，一般 ELF 不会那么多） */
#define MAX_PH 128
    uint64_t null_offsets[MAX_PH], null_sizes[MAX_PH];
    int      null_indices[MAX_PH];
    int      null_count = 0;

    uint64_t other_offsets[MAX_PH], other_sizes[MAX_PH];
    int      other_indices[MAX_PH];
    int      other_count = 0;

    for (int i = 0; i < e_phnum && i < MAX_PH; i++) {
        uint64_t ph_pos = e_phoff + i * e_phentsz;
        if (fseeko(fp, ph_pos, SEEK_SET) != 0) {
            perror("fseeko");
            fclose(fp);
            return 1;
        }

        uint8_t phdr[56];   /* 只读取前 56 字节，足够获取 p_type, p_offset, p_filesz */
        if (fread(phdr, 1, sizeof(phdr), fp) != sizeof(phdr)) {
            fprintf(stderr, "Failed to read program header %d\n", i);
            fclose(fp);
            return 1;
        }

        uint32_t p_type   = read_le32(phdr, 0);
        uint64_t p_offset = read_le64(phdr, 8);
        uint64_t p_filesz = read_le64(phdr, 32);

        if (p_filesz == 0)
            continue;

        /* 非 block 模式下检查段是否超出文件末尾 */
        if (!block_mode && p_offset + p_filesz > file_size) {
            fprintf(stderr, "Warning: segment %d exceeds file size, skipping\n", i);
            continue;
        }

        if (p_filesz > MAX_SEGMENT_BYTES) {
            fprintf(stderr, "Warning: segment %d too large (%llu bytes), skipping\n",
                    i, (unsigned long long)p_filesz);
            continue;
        }

        if (p_type == PT_NULL) {
            null_offsets[null_count] = p_offset;
            null_sizes[null_count]   = p_filesz;
            null_indices[null_count] = i;
            null_count++;
        } else {
            other_offsets[other_count] = p_offset;
            other_sizes[other_count]   = p_filesz;
            other_indices[other_count] = i;
            other_count++;
        }
    }

    hash_info_t info;
    int found = 0;

    /* 先扫描 PT_NULL 段 */
    if (null_count > 0) {
        int ret = scan_candidates(fp, null_offsets, null_sizes, null_indices,
                                  null_count, debug, &info);
        if (ret == 1)
            found = 1;
        else if (ret == -1) {   /* 内存分配失败等严重错误 */
            fclose(fp);
            return 1;
        }
    }

    /* 若未找到，扫描其他类型段 */
    if (!found && other_count > 0) {
        int ret = scan_candidates(fp, other_offsets, other_sizes, other_indices,
                                  other_count, debug, &info);
        if (ret == 1)
            found = 1;
        else if (ret == -1) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);

    if (!found) {
        fprintf(stderr, "No valid HASH segment with OEM metadata found\n");
        return 1;
    }

    //printf("OEM Metadata from %s:\n", filepath);
    printf("  Major Version         : %u\n", info.major);
    printf("  Minor Version         : %u\n", info.minor);
    printf("  Anti-Rollback Version : %u\n", info.arb);

    return 0;
}