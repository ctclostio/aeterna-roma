/*
 * lift_main.c - lifted runner. Linked with one generated batch and lift_rt.c;
 * runs the trials of a job file and writes one result line per trial.
 *
 *   runner.exe --image <flat image> --jobs <job file> [--env <env file>]
 *              --out <result file> [--cov <coverage file>]
 *              [--trace <entry hex> <seed hex>]
 *
 * File formats are in docs/lifted_tier.md. Without --env the model has no TEB
 * page (fs_base 0) and no foreign ranges. With --trace only the named trial
 * runs and its events go to stdout in the reference debugger's trace format;
 * an entry of 0 traces every trial of the job file.
 *
 * A result line whose status is not LM_S_OK has tkind 0 and digest 0; its a
 * and b say where and why the trial stopped and are not for comparison.
 *
 * Coverage file (--cov), one line per trial and one per function:
 *   T <entry> <seed> <mode> <insns_dec> <n_covered_dec> <bitmap hex>
 *   F <entry> <n_insn_dec> <n_covered_dec> <bitmap hex>
 * insns is the number of instructions the trial completed (the result line
 * has it only in step mode). Bit k of the bitmap (byte k / 8, bit k % 8) is
 * the function's k-th instruction in ascending address order; F is the union
 * over its trials.
 *
 * Exit status: 0 when every job was processed, 2 on a usage, file or format
 * error.
 */
#include "lift_rt.h"

#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct trial {
    uint32_t seed, mode;
    uint64_t budget;
} trial;

typedef struct job {
    uint32_t entry;
    uint32_t want_ranges, want_calls; /* counts announced by the F line */
    lift_range *ranges;
    uint32_t n_ranges, cap_ranges;
    lift_callsite *calls;
    uint32_t n_calls, cap_calls;
    trial *trials;
    uint32_t n_trials, cap_trials;
} job;

typedef struct options {
    const char *image, *jobs, *env, *out, *cov;
    int trace;
    uint32_t trace_entry, trace_seed;
} options;

static options g_opt;
static lift_ctx *g_ctx;
static FILE *g_out, *g_cov;
static uint8_t *g_cov_trial, *g_cov_fn; /* one byte per instruction */
static uint32_t g_cov_cap;
static uint64_t g_by_status[LM_S_HARNESS + 1u];
static uint64_t g_insns; /* instructions completed over all trials */

static void die(const char *what, const char *detail) {
    fprintf(stderr, "lift runner: %s%s%s\n", what, detail != NULL ? " " : "", detail != NULL ? detail : "");
    exit(2);
}

static void *xrealloc(void *p, size_t size) {
    void *q = realloc(p, size != 0u ? size : 1u);
    if (q == NULL) {
        die("out of memory", NULL);
    }
    return q;
}

/* Room for one more element in a growing array. */
static void *grow(void *p, uint32_t n, uint32_t *cap, size_t elem) {
    if (n < *cap) {
        return p;
    }
    *cap = *cap != 0u ? *cap * 2u : 16u;
    return xrealloc(p, (size_t)*cap * elem);
}

static uint8_t *read_file(const char *path, size_t *size, size_t extra) {
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long len;
    if (f == NULL) {
        die("cannot open", path);
    }
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        die("cannot read", path);
    }
    buf = xrealloc(NULL, (size_t)len + extra);
    if (fread(buf, 1u, (size_t)len, f) != (size_t)len) {
        die("cannot read", path);
    }
    fclose(f);
    memset(buf + len, 0, extra);
    *size = (size_t)len;
    return buf;
}

/* ---- environment file --------------------------------------------------------- */

static int hex_digit(int ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    ch |= 0x20;
    return ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1;
}

static char *next_token(char **cursor) {
    char *p = *cursor, *start;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }
    if (*p == '\0') {
        *cursor = p;
        return NULL;
    }
    start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
        ++p;
    }
    if (*p != '\0') {
        *p++ = '\0';
    }
    *cursor = p;
    return start;
}

static uint32_t hex_token(char **cursor, const char *path) {
    char *tok = next_token(cursor), *end;
    unsigned long v;
    if (tok == NULL) {
        die("truncated environment file", path);
    }
    v = strtoul(tok, &end, 16);
    if (*end != '\0') {
        die("malformed number in environment file", path);
    }
    return (uint32_t)v;
}

/* Keyword records: fs_base <hex>, image_size <hex>, teb <8192 hex digits>,
 * foreign <lo> <hi_exclusive> (repeated). */
static void load_env(const char *path, uint32_t image_size) {
    size_t size;
    char *text = (char *)read_file(path, &size, 1u), *cursor = text, *key;
    uint8_t *teb = NULL;
    lift_range *foreign = NULL;
    uint32_t n_foreign = 0u, cap_foreign = 0u, fs_base = 0u, i;

    while ((key = next_token(&cursor)) != NULL) {
        if (strcmp(key, "fs_base") == 0) {
            fs_base = hex_token(&cursor, path);
        } else if (strcmp(key, "image_size") == 0) {
            if (hex_token(&cursor, path) != image_size) {
                die("environment file was written for a different image:", path);
            }
        } else if (strcmp(key, "teb") == 0) {
            const char *hex = next_token(&cursor);
            if (hex == NULL || strlen(hex) != 2u * LM_PAGE) {
                die("malformed TEB page in environment file", path);
            }
            teb = xrealloc(teb, LM_PAGE);
            for (i = 0u; i < LM_PAGE; ++i) {
                int hi = hex_digit(hex[2u * i]), lo = hex_digit(hex[2u * i + 1u]);
                if (hi < 0 || lo < 0) {
                    die("malformed TEB page in environment file", path);
                }
                teb[i] = (uint8_t)(hi * 16 + lo);
            }
        } else if (strcmp(key, "foreign") == 0) {
            foreign = grow(foreign, n_foreign, &cap_foreign, sizeof *foreign);
            foreign[n_foreign].lo = hex_token(&cursor, path);
            foreign[n_foreign].hi = hex_token(&cursor, path);
            ++n_foreign;
        } else {
            die("unknown record in environment file:", key);
        }
    }
    if (fs_base != 0u && ((fs_base & (LM_PAGE - 1u)) != 0u || teb == NULL)) {
        die("environment file has an unusable TEB:", path);
    }
    lift_set_env(g_ctx, fs_base, fs_base != 0u ? teb : NULL, foreign, n_foreign);
    free(teb);
    free(foreign);
    free(text);
}

/* ---- jobs -------------------------------------------------------------------------- */

static const lift_fn_entry *find_fn(uint32_t entry) {
    uint32_t lo = 0u, hi = lift_batch_fn_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (lift_batch_fns[mid].entry < entry) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo < lift_batch_fn_count && lift_batch_fns[lo].entry == entry ? &lift_batch_fns[lo] : NULL;
}

static int cmp_callsite(const void *a, const void *b) {
    uint32_t x = ((const lift_callsite *)a)->ret, y = ((const lift_callsite *)b)->ret;
    return (x > y) - (x < y);
}

static void write_bitmap(FILE *f, const uint8_t *cov, uint32_t n) {
    uint32_t k, covered = 0u;
    for (k = 0u; k < n; ++k) {
        covered += cov[k];
    }
    fprintf(f, "%u ", covered);
    for (k = 0u; k < n; k += 8u) {
        uint32_t byte = 0u, bit;
        for (bit = 0u; bit < 8u && k + bit < n; ++bit) {
            byte |= (uint32_t)cov[k + bit] << bit;
        }
        fprintf(f, "%02x", byte);
    }
    fputc('\n', f);
}

static void run_job(job *j) {
    const lift_fn_entry *fe = find_fn(j->entry);
    uint32_t n_insn = fe != NULL ? fe->n_insn : 0u;
    uint32_t t, k;

    qsort(j->calls, j->n_calls, sizeof *j->calls, cmp_callsite);
    lift_set_function(g_ctx, j->ranges, j->n_ranges, j->calls, j->n_calls);
    if (n_insn + 1u > g_cov_cap) {
        g_cov_cap = n_insn + 1u;
        g_cov_trial = xrealloc(g_cov_trial, g_cov_cap);
        g_cov_fn = xrealloc(g_cov_fn, g_cov_cap);
    }
    memset(g_cov_fn, 0, n_insn);

    for (t = 0u; t < j->n_trials; ++t) {
        const trial *tr = &j->trials[t];
        lift_result res = {LM_S_HARNESS, 0u, 0u, 0u, 0u, 0u, 0u};
        if (g_opt.trace && g_opt.trace_entry != 0u &&
            (j->entry != g_opt.trace_entry || tr->seed != g_opt.trace_seed)) {
            continue;
        }
        if (fe != NULL) {
            memset(g_cov_trial, 0, n_insn);
            lift_run_trial(g_ctx, fe->fn, j->entry, tr->seed, tr->mode, tr->budget, g_cov_trial, &res);
            for (k = 0u; k < n_insn; ++k) {
                g_cov_fn[k] |= g_cov_trial[k];
            }
            if (g_cov != NULL) {
                fprintf(g_cov, "T %x %x %u %llu ", j->entry, tr->seed, tr->mode, (unsigned long long)res.insns);
                write_bitmap(g_cov, g_cov_trial, n_insn);
            }
            g_insns += res.insns;
        }
        g_by_status[res.status <= LM_S_HARNESS ? res.status : LM_S_HARNESS]++;
        fprintf(g_out, "%x %x %u %u %u %x %x %016llx %llu\n", j->entry, tr->seed, tr->mode, res.status, res.tkind, res.a,
                res.b, (unsigned long long)res.digest, (unsigned long long)res.steps);
    }
    if (g_cov != NULL && fe != NULL) {
        fprintf(g_cov, "F %x %u ", j->entry, n_insn);
        write_bitmap(g_cov, g_cov_fn, n_insn);
    }
}

static void bad_line(unsigned long line_no) {
    fprintf(stderr, "lift runner: %s:%lu: malformed job line\n", g_opt.jobs, line_no);
    exit(2);
}

static void run_jobs(void) {
    FILE *f = fopen(g_opt.jobs, "rb");
    char line[256];
    unsigned long line_no = 0u;
    job j;
    int open = 0;

    if (f == NULL) {
        die("cannot open", g_opt.jobs);
    }
    memset(&j, 0, sizeof j);
    while (fgets(line, sizeof line, f) != NULL) {
        unsigned a, b, c, d, e;
        unsigned long long budget;
        ++line_no;
        switch (line[0]) {
        case 'F':
            if (open || sscanf(line + 1, "%x %u %u %u %u", &a, &b, &c, &d, &e) != 5) {
                bad_line(line_no);
            }
            j.entry = a;
            j.want_ranges = b;
            j.want_calls = c;
            j.n_ranges = j.n_calls = j.n_trials = 0u;
            open = 1;
            break;
        case 'R':
            if (!open || sscanf(line + 1, "%x %x", &a, &b) != 2) {
                bad_line(line_no);
            }
            j.ranges = grow(j.ranges, j.n_ranges, &j.cap_ranges, sizeof *j.ranges);
            j.ranges[j.n_ranges].lo = a;
            j.ranges[j.n_ranges].hi = b;
            ++j.n_ranges;
            break;
        case 'C':
            if (!open || sscanf(line + 1, "%x %u %u", &a, &b, &c) != 3) {
                bad_line(line_no);
            }
            j.calls = grow(j.calls, j.n_calls, &j.cap_calls, sizeof *j.calls);
            j.calls[j.n_calls].ret = a;
            j.calls[j.n_calls].pop_bytes = b;
            j.calls[j.n_calls].fp_ret = c;
            ++j.n_calls;
            break;
        case 'I': /* stubbed instructions are compiled into the lifted function */
        case 'W': /* data windows only shape the reference's exec view */
            if (!open) {
                bad_line(line_no);
            }
            break;
        case 'T':
            if (!open || sscanf(line + 1, "%x %u %llu", &a, &b, &budget) != 3) {
                bad_line(line_no);
            }
            j.trials = grow(j.trials, j.n_trials, &j.cap_trials, sizeof *j.trials);
            j.trials[j.n_trials].seed = a;
            j.trials[j.n_trials].mode = b;
            j.trials[j.n_trials].budget = budget;
            ++j.n_trials;
            break;
        case 'E':
            if (!open || j.n_ranges != j.want_ranges || j.n_calls != j.want_calls) {
                bad_line(line_no);
            }
            run_job(&j);
            open = 0;
            break;
        case '\r':
        case '\n':
        case '\0':
            break;
        default:
            bad_line(line_no);
        }
    }
    if (open) {
        die("last function is not closed in", g_opt.jobs);
    }
    fclose(f);
    free(j.ranges);
    free(j.calls);
    free(j.trials);
}

static void usage(void) {
    fprintf(stderr, "usage: runner --image <flat image> --jobs <job file> [--env <env file>] --out <result file>\n"
                    "              [--cov <coverage file>] [--trace <entry hex> <seed hex>]\n");
    exit(2);
}

int main(int argc, char **argv) {
    LARGE_INTEGER freq, t0, t1;
    uint8_t *image;
    size_t image_len;
    uint32_t image_size;
    uint64_t total = 0u;
    int i;

    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--trace") == 0 && i + 2 < argc) {
            g_opt.trace = 1;
            g_opt.trace_entry = (uint32_t)strtoul(argv[i + 1], NULL, 16);
            g_opt.trace_seed = (uint32_t)strtoul(argv[i + 2], NULL, 16);
            i += 2;
        } else if (i + 1 >= argc) {
            usage();
        } else if (strcmp(arg, "--image") == 0) {
            g_opt.image = argv[++i];
        } else if (strcmp(arg, "--jobs") == 0) {
            g_opt.jobs = argv[++i];
        } else if (strcmp(arg, "--env") == 0) {
            g_opt.env = argv[++i];
        } else if (strcmp(arg, "--out") == 0) {
            g_opt.out = argv[++i];
        } else if (strcmp(arg, "--cov") == 0) {
            g_opt.cov = argv[++i];
        } else {
            usage();
        }
    }
    if (g_opt.image == NULL || g_opt.jobs == NULL || g_opt.out == NULL) {
        usage();
    }

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    lift_pin_performance_cores();
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    /* The model's image is whole pages; the file's tail page is zero filled. */
    image = read_file(g_opt.image, &image_len, LM_PAGE);
    if (image_len == 0u || image_len > 0x10000000u) {
        die("unusable image", g_opt.image);
    }
    image_size = ((uint32_t)image_len + LM_PAGE - 1u) & ~(LM_PAGE - 1u);

    g_ctx = lift_ctx_create();
    lift_set_image(g_ctx, image, image_size);
    lift_set_thunks(g_ctx, lift_batch_thunks, lift_batch_thunk_count);
    if (g_opt.env != NULL) {
        load_env(g_opt.env, image_size);
    } else {
        lift_set_env(g_ctx, 0u, NULL, NULL, 0u);
    }
    if (g_opt.trace) {
        g_ctx->trace = stdout;
    }

    g_out = fopen(g_opt.out, "wb");
    if (g_out == NULL) {
        die("cannot create", g_opt.out);
    }
    setvbuf(g_out, NULL, _IOFBF, 1u << 16);
    if (g_opt.cov != NULL) {
        g_cov = fopen(g_opt.cov, "wb");
        if (g_cov == NULL) {
            die("cannot create", g_opt.cov);
        }
        setvbuf(g_cov, NULL, _IOFBF, 1u << 16);
    }

    run_jobs();

    if (fclose(g_out) != 0 || (g_cov != NULL && fclose(g_cov) != 0)) {
        die("cannot write results", NULL);
    }
    QueryPerformanceCounter(&t1);
    for (i = 0; i <= (int)LM_S_HARNESS; ++i) {
        total += g_by_status[i];
    }
    fprintf(stderr,
            "lift runner: %llu trials in %.2f s: ok %llu, foreign %llu, budget %llu, unsupported %llu, harness %llu; "
            "%llu instructions\n",
            (unsigned long long)total, (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart,
            (unsigned long long)g_by_status[LM_S_OK], (unsigned long long)g_by_status[LM_S_FOREIGN],
            (unsigned long long)g_by_status[LM_S_BUDGET], (unsigned long long)g_by_status[LM_S_UNSUPPORTED],
            (unsigned long long)g_by_status[LM_S_HARNESS], (unsigned long long)g_insns);
    lift_ctx_destroy(g_ctx);
    free(image);
    free(g_cov_trial);
    free(g_cov_fn);
    return 0;
}
