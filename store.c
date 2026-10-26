#define _POSIX_C_SOURCE 200809L
#include "bank.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define PBKDF2_ITERATIONS 120000
#define SALT_BYTES 16
#define HASH_BYTES 32

typedef enum {
    T_USERS = 0,
    T_ACCOUNTS,
    T_TRANSACTIONS,
    T_LOANS,
    T_FEEDBACK,
    T_JOURNAL,
    T_COUNT
} Table;

static const char *table_names[T_COUNT] = {
    "users.db", "accounts.db", "transactions.db", "loans.db", "feedback.db", "journal.db"
};
/*
 * Traditional POSIX fcntl record locks are process-associated, and closing any
 * descriptor for a file can release that process's locks on it.  These per-file
 * mutexes therefore serialize each process's open/lock/read-or-write/close
 * sequence; fcntl byte-range locks coordinate access with other server processes.
 */
static pthread_mutex_t table_locks[T_COUNT] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER
};
static pthread_mutex_t registration_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Serialize complete financial transactions inside this process. journal.db
 * additionally has a whole-file fcntl lock for cross-process exclusion. */
static pthread_mutex_t financial_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_data_dir[BANK_DATA_DIR_LEN] = "./data";

typedef int (*SerializeFn)(const void *obj, char *line, size_t cap);
typedef void (*SetIdFn)(void *obj, int id);

/* Redo-only write-ahead journal. PREPARED is durable before any financial
 * state is changed. COMMITTED is appended after balances, transaction history
 * and (for loan approvals) loan status are durable. The journal is append-only,
 * so a torn final row can be truncated safely and a torn commit marker leaves
 * the PREPARED row available for recovery. */
typedef struct {
    long long id;
    char state[12];
    int account1_id;
    int account2_id;
    long long account1_balance_after;
    long long account2_balance_after;
    int txn_from_account;
    int txn_to_account;
    char type[24];
    long long amount_paise;
    char actor[BANK_USERNAME_LEN + 1];
    char timestamp[BANK_TIME_LEN];
    char details[BANK_DETAILS_LEN];
    int loan_id;
    char loan_reviewed_by[BANK_USERNAME_LEN + 1];
    char loan_note[BANK_DETAILS_LEN];
} JournalEntry;

static void set_error(char *dst, size_t cap, const char *fmt, ...) {
    if (!dst || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
}

void bank_timestamp(char *out, size_t outcap) {
    if (!out || outcap == 0) return;
    time_t now = time(NULL);
    struct tm tm_now;
    if (!localtime_r(&now, &tm_now)) {
        snprintf(out, outcap, "unknown-time");
        return;
    }
    if (strftime(out, outcap, "%Y-%m-%d_%H:%M:%S", &tm_now) == 0)
        snprintf(out, outcap, "unknown-time");
}

void bank_sanitize_text(char *s) {
    if (!s) return;
    for (; *s; ++s) {
        if (*s == '|' || *s == '\n' || *s == '\r') *s = ' ';
    }
}

int bank_valid_username(const char *s) {
    if (!s || !*s || strlen(s) > BANK_USERNAME_LEN) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.')) return 0;
    }
    return 1;
}

int bank_parse_money(const char *text, long long *paise_out) {
    if (!text || !*text || !paise_out) return -1;
    const char *p = text;
    if (*p == '+') p++;
    if (*p == '-' || !isdigit((unsigned char)*p)) return -1;
    long long rupees = 0;
    while (isdigit((unsigned char)*p)) {
        int digit = *p - '0';
        if (rupees > (LLONG_MAX / 100 - digit) / 10) return -1;
        rupees = rupees * 10 + digit;
        p++;
    }
    int paise = 0;
    if (*p == '.') {
        p++;
        if (!isdigit((unsigned char)*p)) return -1;
        paise = (*p - '0') * 10;
        p++;
        if (isdigit((unsigned char)*p)) {
            paise += *p - '0';
            p++;
        }
        if (isdigit((unsigned char)*p)) return -1;
    }
    if (*p != '\0') return -1;
    if (rupees > (LLONG_MAX - paise) / 100) return -1;
    *paise_out = rupees * 100 + paise;
    return *paise_out > 0 ? 0 : -1;
}

void bank_format_money(long long paise, char *out, size_t outcap) {
    if (!out || outcap == 0) return;
    if (paise < 0) {
        unsigned long long mag = (unsigned long long)(-(paise + 1)) + 1ULL;
        snprintf(out, outcap, "-Rs. %llu.%02llu", mag / 100ULL, mag % 100ULL);
    } else {
        snprintf(out, outcap, "Rs. %lld.%02lld", paise / 100, paise % 100);
    }
}

static void bytes_to_hex(const unsigned char *src, size_t n, char *dst) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        dst[i * 2] = digits[src[i] >> 4];
        dst[i * 2 + 1] = digits[src[i] & 0x0f];
    }
    dst[n * 2] = '\0';
}

static int hex_to_bytes(const char *src, unsigned char *dst, size_t n) {
    if (!src || strlen(src) != n * 2) return -1;
    for (size_t i = 0; i < n; ++i) {
        char a = src[i * 2], b = src[i * 2 + 1];
        int hi = isdigit((unsigned char)a) ? a - '0' :
                 (a >= 'a' && a <= 'f') ? a - 'a' + 10 :
                 (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        int lo = isdigit((unsigned char)b) ? b - '0' :
                 (b >= 'a' && b <= 'f') ? b - 'a' + 10 :
                 (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        dst[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static int make_password_hash(const char *password, char salt_hex[33], char hash_hex[65]) {
    unsigned char salt[SALT_BYTES];
    unsigned char hash[HASH_BYTES];
    if (!password || strlen(password) < 1 || strlen(password) > 256) return -1;
    if (RAND_bytes(salt, sizeof(salt)) != 1) return -1;
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)sizeof(salt),
                          PBKDF2_ITERATIONS, EVP_sha256(), (int)sizeof(hash), hash) != 1)
        return -1;
    bytes_to_hex(salt, sizeof(salt), salt_hex);
    bytes_to_hex(hash, sizeof(hash), hash_hex);
    OPENSSL_cleanse(hash, sizeof(hash));
    return 0;
}

static int verify_password(const char *password, const User *user) {
    if (!password || !user) return 0;
    unsigned char salt[SALT_BYTES], expected[HASH_BYTES], actual[HASH_BYTES];
    if (hex_to_bytes(user->salt_hex, salt, sizeof(salt)) != 0 ||
        hex_to_bytes(user->hash_hex, expected, sizeof(expected)) != 0)
        return 0;
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)sizeof(salt),
                          PBKDF2_ITERATIONS, EVP_sha256(), (int)sizeof(actual), actual) != 1)
        return 0;
    int ok = CRYPTO_memcmp(expected, actual, sizeof(actual)) == 0;
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

static void make_path(Table table, char *out, size_t cap) {
    snprintf(out, cap, "%s/%s", g_data_dir, table_names[table]);
}

static int open_table(Table table, int flags) {
    char path[BANK_DATA_DIR_LEN + 64];
    make_path(table, path, sizeof(path));
    return open(path, flags | O_CLOEXEC, 0600);
}

static int lock_region(int fd, short type, off_t start, off_t len) {
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = SEEK_SET;
    lock.l_start = start;
    lock.l_len = len;
    int cmd = (type == F_UNLCK) ? F_SETLK : F_SETLKW;
    while (fcntl(fd, cmd, &lock) == -1) {
        if (errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int pread_full(int fd, void *buf, size_t count, off_t offset) {
    size_t done = 0;
    while (done < count) {
        ssize_t n = pread(fd, (char *)buf + done, count - done, offset + (off_t)done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static int pwrite_full(int fd, const void *buf, size_t count, off_t offset) {
    size_t done = 0;
    while (done < count) {
        ssize_t n = pwrite(fd, (const char *)buf + done, count - done, offset + (off_t)done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static int read_record_locked(int fd, off_t offset, short lock_type,
                               char row[BANK_RECORD_SIZE]) {
    if (lock_region(fd, lock_type, offset, BANK_RECORD_SIZE) != 0) return -1;
    int result = pread_full(fd, row, BANK_RECORD_SIZE, offset);
    int saved = errno;
    (void)lock_region(fd, F_UNLCK, offset, BANK_RECORD_SIZE);
    errno = saved;
    return result;
}

static int write_record_locked(int fd, off_t offset, const char *line) {
    char record[BANK_RECORD_SIZE];
    size_t len = strlen(line);
    if (len >= BANK_RECORD_SIZE - 1) return -1;
    memset(record, ' ', sizeof(record));
    memcpy(record, line, len);
    /* Keep each fixed-size record a single readable text line. */
    record[BANK_RECORD_SIZE - 1] = '\n';
    return pwrite_full(fd, record, sizeof(record), offset);
}

static void trim_right(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static int split_record(char *row, char **fields, int max_fields) {
    char *nl = strchr(row, '\n');
    if (nl) *nl = '\0';
    trim_right(row);
    int count = 0;
    char *save = NULL;
    char *token = strtok_r(row, "|", &save);
    while (token && count < max_fields) {
        fields[count++] = token;
        token = strtok_r(NULL, "|", &save);
    }
    return count;
}

static int parse_user(char *row, User *u) {
    char *f[10];
    int n = split_record(row, f, 10);
    if (n < 8) return -1;
    memset(u, 0, sizeof(*u));
    u->id = atoi(f[0]);
    snprintf(u->username, sizeof(u->username), "%s", f[1]);
    snprintf(u->salt_hex, sizeof(u->salt_hex), "%s", f[2]);
    snprintf(u->hash_hex, sizeof(u->hash_hex), "%s", f[3]);
    snprintf(u->role, sizeof(u->role), "%s", f[4]);
    u->active = atoi(f[5]);
    snprintf(u->fullname, sizeof(u->fullname), "%s", f[6]);
    u->account_id = atoi(f[7]);
    return u->id > 0 ? 0 : -1;
}

static int parse_account(char *row, Account *a) {
    char *f[8];
    int n = split_record(row, f, 8);
    if (n < 6) return -1;
    memset(a, 0, sizeof(*a));
    a->id = atoi(f[0]);
    snprintf(a->owner1, sizeof(a->owner1), "%s", f[1]);
    snprintf(a->owner2, sizeof(a->owner2), "%s", f[2]);
    a->balance_paise = atoll(f[3]);
    a->active = atoi(f[4]);
    snprintf(a->type, sizeof(a->type), "%s", f[5]);
    return a->id > 0 ? 0 : -1;
}

static int parse_transaction(char *row, Transaction *t) {
    char *f[10];
    int n = split_record(row, f, 10);
    if (n < 8) return -1;
    memset(t, 0, sizeof(*t));
    t->id = atoi(f[0]);
    t->from_account = atoi(f[1]);
    t->to_account = atoi(f[2]);
    snprintf(t->type, sizeof(t->type), "%s", f[3]);
    t->amount_paise = atoll(f[4]);
    snprintf(t->actor, sizeof(t->actor), "%s", f[5]);
    snprintf(t->timestamp, sizeof(t->timestamp), "%s", f[6]);
    snprintf(t->details, sizeof(t->details), "%s", f[7]);
    t->journal_id = (n >= 9) ? atoll(f[8]) : 0;
    return t->id > 0 ? 0 : -1;
}

static int parse_loan(char *row, Loan *l) {
    char *f[12];
    int n = split_record(row, f, 12);
    if (n < 9) return -1;
    memset(l, 0, sizeof(*l));
    l->id = atoi(f[0]);
    l->account_id = atoi(f[1]);
    snprintf(l->applicant, sizeof(l->applicant), "%s", f[2]);
    l->amount_paise = atoll(f[3]);
    snprintf(l->status, sizeof(l->status), "%s", f[4]);
    snprintf(l->assigned_to, sizeof(l->assigned_to), "%s", f[5]);
    snprintf(l->created_at, sizeof(l->created_at), "%s", f[6]);
    snprintf(l->reviewed_by, sizeof(l->reviewed_by), "%s", f[7]);
    snprintf(l->note, sizeof(l->note), "%s", f[8]);
    return l->id > 0 ? 0 : -1;
}

static int parse_feedback(char *row, Feedback *fb) {
    char *f[8];
    int n = split_record(row, f, 8);
    if (n < 4) return -1;
    memset(fb, 0, sizeof(*fb));
    fb->id = atoi(f[0]);
    snprintf(fb->username, sizeof(fb->username), "%s", f[1]);
    snprintf(fb->message, sizeof(fb->message), "%s", f[2]);
    snprintf(fb->timestamp, sizeof(fb->timestamp), "%s", f[3]);
    return fb->id > 0 ? 0 : -1;
}

static int serialize_user(const void *ptr, char *line, size_t cap) {
    const User *u = ptr;
    return snprintf(line, cap, "%d|%s|%s|%s|%s|%d|%s|%d",
                    u->id, u->username, u->salt_hex, u->hash_hex, u->role,
                    u->active, u->fullname, u->account_id) >= (int)cap ? -1 : 0;
}
static int serialize_account(const void *ptr, char *line, size_t cap) {
    const Account *a = ptr;
    return snprintf(line, cap, "%d|%s|%s|%lld|%d|%s",
                    a->id, a->owner1, a->owner2, a->balance_paise,
                    a->active, a->type) >= (int)cap ? -1 : 0;
}
static int serialize_transaction(const void *ptr, char *line, size_t cap) {
    const Transaction *t = ptr;
    return snprintf(line, cap, "%d|%d|%d|%s|%lld|%s|%s|%s|%lld",
                    t->id, t->from_account, t->to_account, t->type,
                    t->amount_paise, t->actor, t->timestamp, t->details, t->journal_id) >= (int)cap ? -1 : 0;
}
static int serialize_loan(const void *ptr, char *line, size_t cap) {
    const Loan *l = ptr;
    return snprintf(line, cap, "%d|%d|%s|%lld|%s|%s|%s|%s|%s",
                    l->id, l->account_id, l->applicant, l->amount_paise,
                    l->status, l->assigned_to, l->created_at,
                    l->reviewed_by, l->note) >= (int)cap ? -1 : 0;
}
static int serialize_feedback(const void *ptr, char *line, size_t cap) {
    const Feedback *fb = ptr;
    return snprintf(line, cap, "%d|%s|%s|%s",
                    fb->id, fb->username, fb->message, fb->timestamp) >= (int)cap ? -1 : 0;
}

static int parse_journal(char *row, JournalEntry *j) {
    char *f[20];
    int n = split_record(row, f, 20);
    if (n < 16) return -1;
    memset(j, 0, sizeof(*j));
    j->id = atoll(f[0]);
    snprintf(j->state, sizeof(j->state), "%s", f[1]);
    j->account1_id = atoi(f[2]);
    j->account2_id = atoi(f[3]);
    j->account1_balance_after = atoll(f[4]);
    j->account2_balance_after = atoll(f[5]);
    j->txn_from_account = atoi(f[6]);
    j->txn_to_account = atoi(f[7]);
    snprintf(j->type, sizeof(j->type), "%s", f[8]);
    j->amount_paise = atoll(f[9]);
    snprintf(j->actor, sizeof(j->actor), "%s", f[10]);
    snprintf(j->timestamp, sizeof(j->timestamp), "%s", f[11]);
    snprintf(j->details, sizeof(j->details), "%s", f[12]);
    j->loan_id = atoi(f[13]);
    snprintf(j->loan_reviewed_by, sizeof(j->loan_reviewed_by), "%s", f[14]);
    snprintf(j->loan_note, sizeof(j->loan_note), "%s", f[15]);
    if (j->id <= 0 || (strcmp(j->state, "PREPARED") != 0 &&
                       strcmp(j->state, "COMMITTED") != 0) ||
        j->account1_id <= 0 || j->account2_id < 0 ||
        j->account1_balance_after < 0 || j->account2_balance_after < 0 ||
        (j->account2_id > 0 && j->account2_id == j->account1_id) ||
        j->amount_paise <= 0 || j->txn_from_account < 0 || j->txn_to_account < 0 ||
        j->loan_id < 0 || !*j->type) return -1;
    if (strcmp(j->type, "DEPOSIT") != 0 && strcmp(j->type, "WITHDRAW") != 0 &&
        strcmp(j->type, "TRANSFER") != 0 && strcmp(j->type, "LOAN_APPROVED") != 0) return -1;
    return 0;
}

static int serialize_journal(const JournalEntry *j, char *line, size_t cap) {
    int n = snprintf(line, cap,
        "%lld|%s|%d|%d|%lld|%lld|%d|%d|%s|%lld|%s|%s|%s|%d|%s|%s",
        j->id, j->state, j->account1_id, j->account2_id,
        j->account1_balance_after, j->account2_balance_after,
        j->txn_from_account, j->txn_to_account, j->type, j->amount_paise,
        j->actor, j->timestamp, j->details, j->loan_id,
        j->loan_reviewed_by, j->loan_note);
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}
static void set_user_id(void *p, int id) { ((User *)p)->id = id; }
static void set_account_id(void *p, int id) { ((Account *)p)->id = id; }
static void set_loan_id(void *p, int id) { ((Loan *)p)->id = id; }
static void set_feedback_id(void *p, int id) { ((Feedback *)p)->id = id; }

static int row_first_id(const char row[BANK_RECORD_SIZE]) {
    char temp[BANK_RECORD_SIZE];
    memcpy(temp, row, sizeof(temp));
    char *nl = strchr(temp, '\n');
    if (nl) *nl = '\0';
    char *end = strchr(temp, '|');
    if (end) *end = '\0';
    trim_right(temp);
    return atoi(temp);
}

static int table_append(Table table, void *object, SetIdFn set_id,
                        SerializeFn serialize, int *id_out) {
    int rc = -1;
    int fd = -1;
    char path[BANK_DATA_DIR_LEN + 64];
    char line[BANK_RECORD_SIZE];
    char row[BANK_RECORD_SIZE];
    struct stat st;

    pthread_mutex_lock(&table_locks[table]);
    fd = open_table(table, O_RDWR | O_CREAT);
    if (fd < 0) goto done;
    if (lock_region(fd, F_WRLCK, 0, 0) != 0) goto done;
    if (fstat(fd, &st) != 0 || st.st_size % BANK_RECORD_SIZE != 0) {
        (void)lock_region(fd, F_UNLCK, 0, 0);
        goto done;
    }
    int max_id = 0;
    off_t count = st.st_size / BANK_RECORD_SIZE;
    for (off_t i = 0; i < count; ++i) {
        if (pread_full(fd, row, sizeof(row), i * BANK_RECORD_SIZE) != 0) continue;
        int v = row_first_id(row);
        if (v > max_id) max_id = v;
    }
    int new_id = max_id + 1;
    set_id(object, new_id);
    if (serialize(object, line, sizeof(line)) != 0) {
        (void)lock_region(fd, F_UNLCK, 0, 0);
        goto done;
    }
    if (write_record_locked(fd, st.st_size, line) != 0) {
        (void)lock_region(fd, F_UNLCK, 0, 0);
        goto done;
    }
    if (fdatasync(fd) != 0) {
        (void)lock_region(fd, F_UNLCK, 0, 0);
        goto done;
    }
    (void)lock_region(fd, F_UNLCK, 0, 0);
    if (id_out) *id_out = new_id;
    rc = 0;

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[table]);
    (void)path;
    return rc;
}

static int table_load_rows(Table table, char (**rows_out)[BANK_RECORD_SIZE], size_t *count_out) {
    if (!rows_out || !count_out) return -1;
    *rows_out = NULL;
    *count_out = 0;
    int fd = -1;
    int rc = -1;
    struct stat st;

    pthread_mutex_lock(&table_locks[table]);
    fd = open_table(table, O_RDONLY);
    if (fd < 0) goto done;
    if (fstat(fd, &st) != 0 || st.st_size % BANK_RECORD_SIZE != 0) goto done;
    size_t count = (size_t)(st.st_size / BANK_RECORD_SIZE);
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    if (count) {
        rows = calloc(count, sizeof(*rows));
        if (!rows) goto done;
    }
    for (size_t i = 0; i < count; ++i) {
        if (read_record_locked(fd, (off_t)i * BANK_RECORD_SIZE, F_RDLCK, rows[i]) != 0) {
            free(rows);
            goto done;
        }
    }
    *rows_out = rows;
    *count_out = count;
    rc = 0;

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[table]);
    return rc;
}

static int find_offset_id_locked(Table table, int fd, int id, off_t *offset_out) {
    struct stat st;
    char row[BANK_RECORD_SIZE];
    if (fstat(fd, &st) != 0 || st.st_size % BANK_RECORD_SIZE != 0) return -1;
    off_t count = st.st_size / BANK_RECORD_SIZE;
    for (off_t i = 0; i < count; ++i) {
        off_t off = i * BANK_RECORD_SIZE;
        if (read_record_locked(fd, off, F_RDLCK, row) != 0) continue;
        if (row_first_id(row) == id) {
            *offset_out = off;
            return 0;
        }
    }
    (void)table;
    return -1;
}

static int find_offset_username_locked(int fd, const char *username, off_t *offset_out) {
    struct stat st;
    char row[BANK_RECORD_SIZE];
    if (fstat(fd, &st) != 0 || st.st_size % BANK_RECORD_SIZE != 0) return -1;
    off_t count = st.st_size / BANK_RECORD_SIZE;
    for (off_t i = 0; i < count; ++i) {
        off_t off = i * BANK_RECORD_SIZE;
        if (read_record_locked(fd, off, F_RDLCK, row) != 0) continue;
        User u;
        if (parse_user(row, &u) == 0 && strcmp(u.username, username) == 0) {
            *offset_out = off;
            return 0;
        }
    }
    return -1;
}


static void storage_fatal_after_prepare(const char *why) {
    dprintf(STDERR_FILENO,
            "FATAL: financial transaction has a durable PREPARED journal entry but "
            "could not finish (%s). Server is stopping; restart it to run journal recovery.\n",
            why ? why : "storage error");
    _exit(87);
}

static void maybe_failpoint(const char *name) {
    const char *configured = getenv("BANK_FAILPOINT");
    if (configured && name && strcmp(configured, name) == 0) {
        dprintf(STDERR_FILENO,
                "TEST FAILPOINT: simulating process crash at %s (journal recovery required).\n",
                name);
        _exit(86);
    }
}

static int repair_partial_tail(int fd, const char *what, char *err, size_t errcap) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        set_error(err, errcap, "Could not inspect %s: %s", what, strerror(errno));
        return -1;
    }
    off_t complete_size = st.st_size - (st.st_size % BANK_RECORD_SIZE);
    if (complete_size != st.st_size) {
        /* Fixed-size append-only tables can only have a torn final append. */
        if (ftruncate(fd, complete_size) != 0 || fdatasync(fd) != 0) {
            set_error(err, errcap, "Could not repair incomplete tail of %s: %s",
                      what, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* Opens and exclusively locks the journal. The table mutex is kept held until
 * journal_close_locked(), because fcntl locks are process-associated. */
static int journal_open_locked(char *err, size_t errcap) {
    pthread_mutex_lock(&table_locks[T_JOURNAL]);
    int fd = open_table(T_JOURNAL, O_RDWR | O_CREAT);
    if (fd < 0) {
        set_error(err, errcap, "Could not open journal.db: %s", strerror(errno));
        pthread_mutex_unlock(&table_locks[T_JOURNAL]);
        return -1;
    }
    if (lock_region(fd, F_WRLCK, 0, 0) != 0) {
        set_error(err, errcap, "Could not lock journal.db: %s", strerror(errno));
        close(fd);
        pthread_mutex_unlock(&table_locks[T_JOURNAL]);
        return -1;
    }
    if (repair_partial_tail(fd, "journal.db", err, errcap) != 0) {
        (void)lock_region(fd, F_UNLCK, 0, 0);
        close(fd);
        pthread_mutex_unlock(&table_locks[T_JOURNAL]);
        return -1;
    }
    return fd;
}

static void journal_close_locked(int fd) {
    if (fd >= 0) {
        if (lock_region(fd, F_UNLCK, 0, 0) != 0)
            dprintf(STDERR_FILENO, "WARNING: could not explicitly unlock journal.db: %s\n", strerror(errno));
        if (close(fd) != 0)
            dprintf(STDERR_FILENO, "WARNING: close(journal.db) failed: %s\n", strerror(errno));
        /* Closing the descriptor releases the process-associated fcntl lock even
         * when an explicit unlock reports an error. */
    }
    pthread_mutex_unlock(&table_locks[T_JOURNAL]);
}

static int journal_append_state(int fd, JournalEntry *entry, const char *state,
                                int allocate_id, char *err, size_t errcap) {
    struct stat st;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    if (!entry || fstat(fd, &st) != 0 || st.st_size % BANK_RECORD_SIZE != 0) {
        set_error(err, errcap, "Could not inspect journal.db before append.");
        return -1;
    }
    if (allocate_id) {
        /* Journal entries are append-only and strictly increase by ID; a
         * COMMITTED marker repeats the immediately preceding PREPARED ID. */
        long long last_id = 0;
        if (st.st_size > 0) {
            JournalEntry previous;
            off_t last_offset = st.st_size - BANK_RECORD_SIZE;
            if (pread_full(fd, row, sizeof(row), last_offset) != 0 ||
                parse_journal(row, &previous) != 0) {
                set_error(err, errcap, "Journal's last complete record is corrupt.");
                return -1;
            }
            last_id = previous.id;
        }
        if (last_id == LLONG_MAX) {
            set_error(err, errcap, "Journal transaction identifier space exhausted.");
            return -1;
        }
        entry->id = last_id + 1;
    }
    snprintf(entry->state, sizeof(entry->state), "%s", state);
    if (serialize_journal(entry, line, sizeof(line)) != 0 ||
        write_record_locked(fd, st.st_size, line) != 0) {
        set_error(err, errcap, "Could not append %s journal record: %s", state, strerror(errno));
        return -1;
    }
    /* A complete PREPARED record may already be visible even if fdatasync fails.
     * Stop immediately; startup recovery will decide the durable outcome. */
    if (fdatasync(fd) != 0) {
        dprintf(STDERR_FILENO, "FATAL: fdatasync(journal.db) failed: %s\n", strerror(errno));
        _exit(87);
    }
    return 0;
}

static int journal_load_pending(int fd, JournalEntry **pending_out, size_t *count_out,
                                char *err, size_t errcap) {
    struct stat st;
    char row[BANK_RECORD_SIZE];
    JournalEntry *latest = NULL;
    size_t used = 0;
    if (!pending_out || !count_out || fstat(fd, &st) != 0 ||
        st.st_size % BANK_RECORD_SIZE != 0) {
        set_error(err, errcap, "Could not inspect journal records.");
        return -1;
    }
    size_t capacity = (size_t)(st.st_size / BANK_RECORD_SIZE);
    if (capacity) {
        latest = calloc(capacity, sizeof(*latest));
        if (!latest) {
            set_error(err, errcap, "Out of memory reading transaction journal.");
            return -1;
        }
    }
    for (off_t off = 0; off < st.st_size; off += BANK_RECORD_SIZE) {
        JournalEntry parsed;
        if (pread_full(fd, row, sizeof(row), off) != 0 || parse_journal(row, &parsed) != 0) {
            free(latest);
            set_error(err, errcap, "Journal contains a corrupt complete record at offset %lld.",
                      (long long)off);
            return -1;
        }
        if (used > 0 && latest[used - 1].id == parsed.id) {
            latest[used - 1] = parsed; /* PREPARED followed immediately by COMMITTED. */
        } else {
            if (used > 0 && parsed.id <= latest[used - 1].id) {
                free(latest);
                set_error(err, errcap, "Journal transaction IDs are not in append order.");
                return -1;
            }
            latest[used++] = parsed;
        }
    }
    size_t pending = 0;
    for (size_t i = 0; i < used; ++i) {
        if (strcmp(latest[i].state, "PREPARED") == 0) latest[pending++] = latest[i];
    }
    *pending_out = latest;
    *count_out = pending;
    return 0;
}

static int redo_account_balances(const JournalEntry *entry, char *err, size_t errcap) {
    int fd = -1, result = -1;
    off_t off1 = -1, off2 = -1, first_off, second_off = -1;
    int first_locked = 0, second_locked = 0;
    char row1[BANK_RECORD_SIZE], row2[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    Account a1, a2;
    pthread_mutex_lock(&table_locks[T_ACCOUNTS]);
    fd = open_table(T_ACCOUNTS, O_RDWR);
    if (fd < 0) {
        set_error(err, errcap, "Recovery could not open accounts.db: %s", strerror(errno));
        goto done;
    }
    if (find_offset_id_locked(T_ACCOUNTS, fd, entry->account1_id, &off1) != 0) {
        set_error(err, errcap, "Recovery could not find account #%d.", entry->account1_id);
        goto done;
    }
    if (entry->account2_id > 0 &&
        find_offset_id_locked(T_ACCOUNTS, fd, entry->account2_id, &off2) != 0) {
        set_error(err, errcap, "Recovery could not find account #%d.", entry->account2_id);
        goto done;
    }
    first_off = off1;
    if (off2 >= 0) {
        second_off = off2;
        if (second_off < first_off) {
            off_t temp = first_off; first_off = second_off; second_off = temp;
        }
    }
    if (lock_region(fd, F_WRLCK, first_off, BANK_RECORD_SIZE) != 0) {
        set_error(err, errcap, "Recovery could not lock first account record.");
        goto done;
    }
    first_locked = 1;
    if (second_off >= 0) {
        if (lock_region(fd, F_WRLCK, second_off, BANK_RECORD_SIZE) != 0) {
            set_error(err, errcap, "Recovery could not lock second account record.");
            goto done;
        }
        second_locked = 1;
    }
    if (pread_full(fd, row1, sizeof(row1), off1) != 0 || parse_account(row1, &a1) != 0 ||
        a1.id != entry->account1_id) {
        set_error(err, errcap, "Recovery could not read account #%d.", entry->account1_id);
        goto done;
    }
    a1.balance_paise = entry->account1_balance_after;
    if (entry->account2_id > 0) {
        if (pread_full(fd, row2, sizeof(row2), off2) != 0 || parse_account(row2, &a2) != 0 ||
            a2.id != entry->account2_id) {
            set_error(err, errcap, "Recovery could not read account #%d.", entry->account2_id);
            goto done;
        }
        a2.balance_paise = entry->account2_balance_after;
    }
    if (serialize_account(&a1, line, sizeof(line)) != 0 || write_record_locked(fd, off1, line) != 0) {
        set_error(err, errcap, "Recovery could not write account #%d.", entry->account1_id);
        goto done;
    }
    if (entry->account2_id > 0) {
        if (serialize_account(&a2, line, sizeof(line)) != 0 || write_record_locked(fd, off2, line) != 0) {
            set_error(err, errcap, "Recovery could not write account #%d.", entry->account2_id);
            goto done;
        }
    }
    if (fdatasync(fd) != 0) {
        set_error(err, errcap, "Recovery could not sync account balances: %s", strerror(errno));
        goto done;
    }
    result = 0;

done:
    if (second_locked) (void)lock_region(fd, F_UNLCK, second_off, BANK_RECORD_SIZE);
    if (first_locked) (void)lock_region(fd, F_UNLCK, first_off, BANK_RECORD_SIZE);
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_ACCOUNTS]);
    return result;
}

static int append_transaction_once(const JournalEntry *entry, char *err, size_t errcap) {
    int fd = -1, result = -1;
    struct stat st;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    int locked = 0;
    pthread_mutex_lock(&table_locks[T_TRANSACTIONS]);
    fd = open_table(T_TRANSACTIONS, O_RDWR | O_CREAT);
    if (fd < 0) {
        set_error(err, errcap, "Could not open transactions.db: %s", strerror(errno));
        goto done;
    }
    if (lock_region(fd, F_WRLCK, 0, 0) != 0) {
        set_error(err, errcap, "Could not lock transactions.db: %s", strerror(errno));
        goto done;
    }
    locked = 1;
    if (repair_partial_tail(fd, "transactions.db", err, errcap) != 0 || fstat(fd, &st) != 0) goto done;
    int max_id = 0;
    for (off_t off = 0; off < st.st_size; off += BANK_RECORD_SIZE) {
        Transaction old;
        if (pread_full(fd, row, sizeof(row), off) != 0 || parse_transaction(row, &old) != 0) {
            set_error(err, errcap, "transactions.db contains a corrupt complete record.");
            goto done;
        }
        if (old.journal_id == entry->id) { result = 0; goto done; }
        if (old.id > max_id) max_id = old.id;
    }
    if (max_id == INT_MAX) {
        set_error(err, errcap, "Transaction identifier space exhausted.");
        goto done;
    }
    Transaction t;
    memset(&t, 0, sizeof(t));
    t.id = max_id + 1;
    t.from_account = entry->txn_from_account;
    t.to_account = entry->txn_to_account;
    snprintf(t.type, sizeof(t.type), "%s", entry->type);
    t.amount_paise = entry->amount_paise;
    snprintf(t.actor, sizeof(t.actor), "%s", entry->actor);
    snprintf(t.timestamp, sizeof(t.timestamp), "%s", entry->timestamp);
    snprintf(t.details, sizeof(t.details), "%s", entry->details);
    t.journal_id = entry->id;
    if (serialize_transaction(&t, line, sizeof(line)) != 0 ||
        write_record_locked(fd, st.st_size, line) != 0) {
        set_error(err, errcap, "Could not append transaction history row: %s", strerror(errno));
        goto done;
    }
    if (fdatasync(fd) != 0) {
        set_error(err, errcap, "Could not sync transaction history: %s", strerror(errno));
        goto done;
    }
    result = 0;

done:
    if (locked) (void)lock_region(fd, F_UNLCK, 0, 0);
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_TRANSACTIONS]);
    return result;
}

static int redo_loan_approval(const JournalEntry *entry, char *err, size_t errcap) {
    int fd = -1, result = -1;
    off_t off;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    Loan loan;
    if (entry->loan_id <= 0) return 0;
    pthread_mutex_lock(&table_locks[T_LOANS]);
    fd = open_table(T_LOANS, O_RDWR);
    if (fd < 0) {
        set_error(err, errcap, "Recovery could not open loans.db: %s", strerror(errno));
        goto done;
    }
    if (find_offset_id_locked(T_LOANS, fd, entry->loan_id, &off) != 0) {
        set_error(err, errcap, "Recovery could not find loan #%d.", entry->loan_id);
        goto done;
    }
    if (lock_region(fd, F_WRLCK, off, BANK_RECORD_SIZE) != 0) {
        set_error(err, errcap, "Recovery could not lock loan #%d.", entry->loan_id);
        goto done;
    }
    if (pread_full(fd, row, sizeof(row), off) != 0 || parse_loan(row, &loan) != 0) {
        set_error(err, errcap, "Recovery could not read loan #%d.", entry->loan_id);
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (strcmp(loan.status, "APPROVED") != 0) {
        snprintf(loan.status, sizeof(loan.status), "APPROVED");
        snprintf(loan.reviewed_by, sizeof(loan.reviewed_by), "%s", entry->loan_reviewed_by);
        snprintf(loan.note, sizeof(loan.note), "%s", entry->loan_note);
        if (serialize_loan(&loan, line, sizeof(line)) != 0 || write_record_locked(fd, off, line) != 0) {
            set_error(err, errcap, "Recovery could not save loan #%d approval.", entry->loan_id);
            (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
            goto done;
        }
        if (fdatasync(fd) != 0) {
            set_error(err, errcap, "Recovery could not sync loan #%d: %s", entry->loan_id, strerror(errno));
            (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
            goto done;
        }
    }
    (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
    result = 0;

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_LOANS]);
    return result;
}

static int recover_journal_locked(int journal_fd, char *err, size_t errcap) {
    JournalEntry *pending = NULL;
    size_t count = 0;
    if (journal_load_pending(journal_fd, &pending, &count, err, errcap) != 0) return -1;
    for (size_t i = 0; i < count; ++i) {
        JournalEntry *entry = &pending[i];
        if (redo_account_balances(entry, err, errcap) != 0 ||
            append_transaction_once(entry, err, errcap) != 0 ||
            redo_loan_approval(entry, err, errcap) != 0) {
            free(pending);
            return -1;
        }
        if (journal_append_state(journal_fd, entry, "COMMITTED", 0, err, errcap) != 0) {
            free(pending);
            return -1;
        }
        fprintf(stderr, "Recovered transaction journal #%lld (%s).\n", entry->id, entry->type);
    }
    free(pending);
    return 0;
}

static int begin_financial_transaction(int *journal_fd, char *err, size_t errcap) {
    pthread_mutex_lock(&financial_mutex);
    int fd = journal_open_locked(err, errcap);
    if (fd < 0) {
        pthread_mutex_unlock(&financial_mutex);
        return -1;
    }
    if (recover_journal_locked(fd, err, errcap) != 0) {
        journal_close_locked(fd);
        pthread_mutex_unlock(&financial_mutex);
        return -1;
    }
    *journal_fd = fd;
    return 0;
}

static void end_financial_transaction(int journal_fd) {
    journal_close_locked(journal_fd);
    pthread_mutex_unlock(&financial_mutex);
}

static int recover_journal_at_startup(char *err, size_t errcap) {
    int journal_fd;
    if (begin_financial_transaction(&journal_fd, err, errcap) != 0) return -1;
    end_financial_transaction(journal_fd);
    return 0;
}


int store_find_user(const char *username, User *out) {
    if (!username || !out) return -1;
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t count = 0;
    if (table_load_rows(T_USERS, &rows, &count) != 0) return -1;
    int found = -1;
    for (size_t i = 0; i < count; ++i) {
        User u;
        char copy[BANK_RECORD_SIZE];
        memcpy(copy, rows[i], sizeof(copy));
        if (parse_user(copy, &u) == 0 && strcmp(u.username, username) == 0) {
            *out = u;
            found = 0;
            break;
        }
    }
    free(rows);
    return found;
}

int store_find_account(int account_id, Account *out) {
    if (account_id <= 0 || !out) return -1;
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t count = 0;
    if (table_load_rows(T_ACCOUNTS, &rows, &count) != 0) return -1;
    int found = -1;
    for (size_t i = 0; i < count; ++i) {
        Account a;
        char copy[BANK_RECORD_SIZE];
        memcpy(copy, rows[i], sizeof(copy));
        if (parse_account(copy, &a) == 0 && a.id == account_id) {
            *out = a;
            found = 0;
            break;
        }
    }
    free(rows);
    return found;
}

static int add_user_record(User *user) {
    return table_append(T_USERS, user, set_user_id, serialize_user, &user->id);
}
static int add_account_record(Account *account) {
    return table_append(T_ACCOUNTS, account, set_account_id, serialize_account, &account->id);
}
static int add_loan_record(Loan *loan) {
    return table_append(T_LOANS, loan, set_loan_id, serialize_loan, &loan->id);
}
static int add_feedback_record(Feedback *feedback) {
    return table_append(T_FEEDBACK, feedback, set_feedback_id, serialize_feedback, &feedback->id);
}

static int update_user_field(const char *username, const char *new_password,
                             const char *new_salt, const char *new_hash,
                             const char *new_fullname, int active_override,
                             int active_value, const char *old_password,
                             char *err, size_t errcap) {
    int fd = -1, result = -1;
    off_t off;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    User u;
    pthread_mutex_lock(&table_locks[T_USERS]);
    fd = open_table(T_USERS, O_RDWR);
    if (fd < 0) goto done;
    if (find_offset_username_locked(fd, username, &off) != 0) {
        set_error(err, errcap, "User '%s' was not found.", username);
        goto done;
    }
    if (lock_region(fd, F_WRLCK, off, BANK_RECORD_SIZE) != 0) goto done;
    if (pread_full(fd, row, sizeof(row), off) != 0 || parse_user(row, &u) != 0) {
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (old_password && !verify_password(old_password, &u)) {
        set_error(err, errcap, "Current password is incorrect.");
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (new_password) {
        snprintf(u.salt_hex, sizeof(u.salt_hex), "%s", new_salt);
        snprintf(u.hash_hex, sizeof(u.hash_hex), "%s", new_hash);
    }
    if (new_fullname) snprintf(u.fullname, sizeof(u.fullname), "%s", new_fullname);
    if (active_override) u.active = active_value;
    if (serialize_user(&u, line, sizeof(line)) != 0 || write_record_locked(fd, off, line) != 0) {
        set_error(err, errcap, "Could not write user record.");
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (fdatasync(fd) != 0) {
        set_error(err, errcap, "Could not sync user record: %s", strerror(errno));
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
    result = 0;

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_USERS]);
    return result;
}

static int update_account(int account_id, const Account *replacement,
                          int active_override, int active_value,
                          const char *owner2_override, const char *type_override,
                          char *err, size_t errcap) {
    int fd = -1, result = -1;
    off_t off;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    Account a;
    pthread_mutex_lock(&table_locks[T_ACCOUNTS]);
    fd = open_table(T_ACCOUNTS, O_RDWR);
    if (fd < 0) goto done;
    if (find_offset_id_locked(T_ACCOUNTS, fd, account_id, &off) != 0) {
        set_error(err, errcap, "Account %d was not found.", account_id);
        goto done;
    }
    if (lock_region(fd, F_WRLCK, off, BANK_RECORD_SIZE) != 0) goto done;
    if (pread_full(fd, row, sizeof(row), off) != 0 || parse_account(row, &a) != 0) {
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (active_override && a.active == (active_value ? 1 : 0)) {
        set_error(err, errcap, "Account #%d is already %s.", account_id,
                  active_value ? "ACTIVE" : "INACTIVE");
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (replacement) {
        /* The replacement is used for administrative metadata, never a stale balance write. */
        snprintf(a.owner1, sizeof(a.owner1), "%s", replacement->owner1);
        snprintf(a.owner2, sizeof(a.owner2), "%s", replacement->owner2);
        snprintf(a.type, sizeof(a.type), "%s", replacement->type);
    }
    if (active_override) a.active = active_value;
    if (owner2_override) snprintf(a.owner2, sizeof(a.owner2), "%s", owner2_override);
    if (type_override) snprintf(a.type, sizeof(a.type), "%s", type_override);
    if (serialize_account(&a, line, sizeof(line)) != 0 || write_record_locked(fd, off, line) != 0) {
        set_error(err, errcap, "Could not write account record.");
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (fdatasync(fd) != 0) {
        set_error(err, errcap, "Could not sync account record: %s", strerror(errno));
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
    result = 0;

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_ACCOUNTS]);
    return result;
}

static int account_attach_joint(int account_id, const char *joint_username,
                                char *err, size_t errcap) {
    int fd = -1, result = -1;
    off_t off;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    Account a;
    pthread_mutex_lock(&table_locks[T_ACCOUNTS]);
    fd = open_table(T_ACCOUNTS, O_RDWR);
    if (fd < 0) goto done;
    if (find_offset_id_locked(T_ACCOUNTS, fd, account_id, &off) != 0) {
        set_error(err, errcap, "Account %d was not found.", account_id);
        goto done;
    }
    if (lock_region(fd, F_WRLCK, off, BANK_RECORD_SIZE) != 0) goto done;
    if (pread_full(fd, row, sizeof(row), off) != 0 || parse_account(row, &a) != 0) {
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (!a.active) {
        set_error(err, errcap, "The target account is inactive.");
    } else if (strcmp(a.owner2, "-") != 0 || strcmp(a.type, "JOINT") == 0) {
        set_error(err, errcap, "This account already has a joint holder.");
    } else if (strcmp(a.owner1, joint_username) == 0) {
        set_error(err, errcap, "The joint holder must be a different user.");
    } else {
        snprintf(a.owner2, sizeof(a.owner2), "%s", joint_username);
        snprintf(a.type, sizeof(a.type), "JOINT");
        if (serialize_account(&a, line, sizeof(line)) == 0 &&
            write_record_locked(fd, off, line) == 0 && fdatasync(fd) == 0) {
            result = 0;
        } else {
            set_error(err, errcap, "Could not durably update the joint account record: %s", strerror(errno));
        }
    }
    (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_ACCOUNTS]);
    return result;
}

int store_register_customer(const char *username, const char *password,
                            const char *fullname, int is_joint,
                            int joint_account_id, User *created,
                            char *err, size_t errcap) {
    if (!bank_valid_username(username)) {
        set_error(err, errcap, "Username must be 1-32 characters using letters, digits, dot, underscore or hyphen.");
        return -1;
    }
    if (!password || strlen(password) < 8 || strlen(password) > 256) {
        set_error(err, errcap, "Password must be at least 8 characters.");
        return -1;
    }
    if (!fullname || !*fullname) {
        set_error(err, errcap, "Full name is required.");
        return -1;
    }
    pthread_mutex_lock(&registration_mutex);
    User existing;
    if (store_find_user(username, &existing) == 0) {
        pthread_mutex_unlock(&registration_mutex);
        set_error(err, errcap, "That username already exists.");
        return -1;
    }

    char clean_name[BANK_NAME_LEN];
    snprintf(clean_name, sizeof(clean_name), "%s", fullname);
    bank_sanitize_text(clean_name);

    int account_id = 0;
    if (is_joint) {
        Account target;
        if (store_find_account(joint_account_id, &target) != 0) {
            pthread_mutex_unlock(&registration_mutex);
            set_error(err, errcap, "The account number does not exist.");
            return -1;
        }
        if (account_attach_joint(joint_account_id, username, err, errcap) != 0) {
            pthread_mutex_unlock(&registration_mutex);
            return -1;
        }
        account_id = joint_account_id;
    } else {
        Account a;
        memset(&a, 0, sizeof(a));
        snprintf(a.owner1, sizeof(a.owner1), "%s", username);
        snprintf(a.owner2, sizeof(a.owner2), "-");
        a.balance_paise = 0;
        a.active = 1;
        snprintf(a.type, sizeof(a.type), "SINGLE");
        if (add_account_record(&a) != 0) {
            pthread_mutex_unlock(&registration_mutex);
            set_error(err, errcap, "Could not create the account file record.");
            return -1;
        }
        account_id = a.id;
    }

    User u;
    memset(&u, 0, sizeof(u));
    snprintf(u.username, sizeof(u.username), "%s", username);
    snprintf(u.role, sizeof(u.role), "%s", is_joint ? "JOINT" : "CUSTOMER");
    u.active = 1;
    snprintf(u.fullname, sizeof(u.fullname), "%s", clean_name);
    u.account_id = account_id;
    if (make_password_hash(password, u.salt_hex, u.hash_hex) != 0 || add_user_record(&u) != 0) {
        /* Keep a failed first-owner account disabled instead of leaving it usable without a user. */
        if (!is_joint) (void)store_set_account_active(account_id, 0, NULL, 0);
        else {
            /* Best-effort rollback for a failed joint-user insert. */
            Account a;
            if (store_find_account(account_id, &a) == 0) {
                (void)update_account(account_id, NULL, 0, 0, "-", "SINGLE", NULL, 0);
            }
        }
        pthread_mutex_unlock(&registration_mutex);
        set_error(err, errcap, "Could not create the user record.");
        return -1;
    }
    if (created) *created = u;
    pthread_mutex_unlock(&registration_mutex);
    return 0;
}

int store_add_staff(const char *username, const char *password,
                    const char *fullname, const char *role,
                    char *err, size_t errcap) {
    if (!role || (strcmp(role, "EMPLOYEE") != 0 && strcmp(role, "MANAGER") != 0)) {
        set_error(err, errcap, "Staff role must be EMPLOYEE or MANAGER.");
        return -1;
    }
    if (!bank_valid_username(username)) {
        set_error(err, errcap, "Invalid username.");
        return -1;
    }
    if (!password || strlen(password) < 8 || strlen(password) > 256) {
        set_error(err, errcap, "Password must be at least 8 characters.");
        return -1;
    }
    if (!fullname || !*fullname) {
        set_error(err, errcap, "Full name is required.");
        return -1;
    }
    pthread_mutex_lock(&registration_mutex);
    User existing;
    if (store_find_user(username, &existing) == 0) {
        pthread_mutex_unlock(&registration_mutex);
        set_error(err, errcap, "That username already exists.");
        return -1;
    }
    User u;
    memset(&u, 0, sizeof(u));
    snprintf(u.username, sizeof(u.username), "%s", username);
    snprintf(u.role, sizeof(u.role), "%s", role);
    u.active = 1;
    snprintf(u.fullname, sizeof(u.fullname), "%s", fullname);
    bank_sanitize_text(u.fullname);
    u.account_id = 0;
    if (make_password_hash(password, u.salt_hex, u.hash_hex) != 0 || add_user_record(&u) != 0) {
        pthread_mutex_unlock(&registration_mutex);
        set_error(err, errcap, "Could not create staff user.");
        return -1;
    }
    pthread_mutex_unlock(&registration_mutex);
    return 0;
}

int store_authenticate(const char *username, const char *password,
                       const char *requested_role, User *out,
                       char *err, size_t errcap) {
    User u;
    if (store_find_user(username, &u) != 0) {
        set_error(err, errcap, "Invalid username or password.");
        return -1;
    }
    if (strcmp(u.role, requested_role) != 0) {
        set_error(err, errcap, "That user does not have the requested login role.");
        return -1;
    }
    if (!u.active) {
        set_error(err, errcap, "This user is inactive. Contact the bank manager.");
        return -1;
    }
    if (!verify_password(password, &u)) {
        set_error(err, errcap, "Invalid username or password.");
        return -1;
    }
    if (u.account_id > 0) {
        Account a;
        if (store_find_account(u.account_id, &a) != 0 || !a.active) {
            set_error(err, errcap, "This account is inactive. Contact the bank manager.");
            return -1;
        }
    }
    if (out) *out = u;
    return 0;
}

int store_change_password(const char *username, const char *old_password,
                          const char *new_password, char *err, size_t errcap) {
    char salt[33], hash[65];
    if (!new_password || strlen(new_password) < 8 || strlen(new_password) > 256) {
        set_error(err, errcap, "New password must be at least 8 characters.");
        return -1;
    }
    if (make_password_hash(new_password, salt, hash) != 0) {
        set_error(err, errcap, "Password hashing failed.");
        return -1;
    }
    return update_user_field(username, new_password, salt, hash, NULL,
                             0, 0, old_password, err, errcap);
}

int store_update_fullname(const char *username, const char *fullname,
                          char *err, size_t errcap) {
    if (!fullname || !*fullname) {
        set_error(err, errcap, "Full name cannot be empty.");
        return -1;
    }
    char clean[BANK_NAME_LEN];
    snprintf(clean, sizeof(clean), "%s", fullname);
    bank_sanitize_text(clean);
    return update_user_field(username, NULL, NULL, NULL, clean,
                             0, 0, NULL, err, errcap);
}

int store_set_account_active(int account_id, int active,
                             char *err, size_t errcap) {
    return update_account(account_id, NULL, 1, active ? 1 : 0, NULL, NULL, err, errcap);
}

int store_modify_account_owner_name(int account_id, const char *fullname,
                                    char *err, size_t errcap) {
    Account a;
    if (store_find_account(account_id, &a) != 0) {
        set_error(err, errcap, "Account %d was not found.", account_id);
        return -1;
    }
    return store_update_fullname(a.owner1, fullname, err, errcap);
}

int store_account_view(int account_id, Account *account, User *owner1, User *owner2) {
    Account a;
    if (store_find_account(account_id, &a) != 0) return -1;
    if (account) *account = a;
    if (owner1) {
        if (store_find_user(a.owner1, owner1) != 0) memset(owner1, 0, sizeof(*owner1));
    }
    if (owner2) {
        if (strcmp(a.owner2, "-") == 0 || store_find_user(a.owner2, owner2) != 0)
            memset(owner2, 0, sizeof(*owner2));
    }
    return 0;
}

int store_money_action(int from_account, int to_account, const char *type,
                       long long amount_paise, const char *actor,
                       char *err, size_t errcap) {
    if (amount_paise <= 0) {
        set_error(err, errcap, "Amount must be greater than zero.");
        return -1;
    }
    int is_transfer = strcmp(type, "TRANSFER") == 0;
    int is_deposit = strcmp(type, "DEPOSIT") == 0;
    int is_withdraw = strcmp(type, "WITHDRAW") == 0;
    if (!is_transfer && !is_deposit && !is_withdraw) {
        set_error(err, errcap, "Unsupported money operation.");
        return -1;
    }
    if (from_account <= 0 || (is_transfer && (to_account <= 0 || to_account == from_account))) {
        set_error(err, errcap, "Choose a different, valid destination account.");
        return -1;
    }

    int journal_fd = -1, fd = -1, result = -1;
    off_t source_off = -1, destination_off = -1;
    off_t first_lock_off = -1, second_lock_off = -1;
    int first_locked = 0, second_locked = 0, account_mutex_locked = 0;
    char source_row[BANK_RECORD_SIZE], destination_row[BANK_RECORD_SIZE];
    char source_line[BANK_RECORD_SIZE], destination_line[BANK_RECORD_SIZE];
    Account source, destination;
    JournalEntry entry;

    if (begin_financial_transaction(&journal_fd, err, errcap) != 0) return -1;
    pthread_mutex_lock(&table_locks[T_ACCOUNTS]);
    account_mutex_locked = 1;
    fd = open_table(T_ACCOUNTS, O_RDWR);
    if (fd < 0) {
        set_error(err, errcap, "Could not open accounts.db: %s", strerror(errno));
        goto done;
    }
    if (find_offset_id_locked(T_ACCOUNTS, fd, from_account, &source_off) != 0) {
        set_error(err, errcap, "Source account does not exist.");
        goto done;
    }
    if (is_transfer && find_offset_id_locked(T_ACCOUNTS, fd, to_account, &destination_off) != 0) {
        set_error(err, errcap, "Destination account does not exist.");
        goto done;
    }

    first_lock_off = source_off;
    second_lock_off = destination_off;
    if (is_transfer && first_lock_off > second_lock_off) {
        off_t temp = first_lock_off;
        first_lock_off = second_lock_off;
        second_lock_off = temp;
    }
    if (lock_region(fd, F_WRLCK, first_lock_off, BANK_RECORD_SIZE) != 0) {
        set_error(err, errcap, "Could not lock source account: %s", strerror(errno));
        goto done;
    }
    first_locked = 1;
    if (is_transfer) {
        if (lock_region(fd, F_WRLCK, second_lock_off, BANK_RECORD_SIZE) != 0) {
            set_error(err, errcap, "Could not lock destination account: %s", strerror(errno));
            goto done;
        }
        second_locked = 1;
    }

    if (pread_full(fd, source_row, sizeof(source_row), source_off) != 0 ||
        parse_account(source_row, &source) != 0 || source.id != from_account) {
        set_error(err, errcap, "Could not read the source account.");
        goto done;
    }
    if (is_transfer &&
        (pread_full(fd, destination_row, sizeof(destination_row), destination_off) != 0 ||
         parse_account(destination_row, &destination) != 0 || destination.id != to_account)) {
        set_error(err, errcap, "Could not read the destination account.");
        goto done;
    }
    if (!source.active) {
        set_error(err, errcap, "Source account is inactive.");
        goto done;
    }
    if (is_transfer && !destination.active) {
        set_error(err, errcap, "Destination account is inactive.");
        goto done;
    }

    if (is_withdraw || is_transfer) {
        if (source.balance_paise < amount_paise) {
            set_error(err, errcap, "Insufficient balance.");
            goto done;
        }
        source.balance_paise -= amount_paise;
    } else {
        if (LLONG_MAX - source.balance_paise < amount_paise) {
            set_error(err, errcap, "Balance overflow.");
            goto done;
        }
        source.balance_paise += amount_paise;
    }
    if (is_transfer) {
        if (LLONG_MAX - destination.balance_paise < amount_paise) {
            set_error(err, errcap, "Destination balance overflow.");
            goto done;
        }
        destination.balance_paise += amount_paise;
    }

    memset(&entry, 0, sizeof(entry));
    entry.account1_id = from_account;
    entry.account1_balance_after = source.balance_paise;
    entry.account2_id = is_transfer ? to_account : 0;
    entry.account2_balance_after = is_transfer ? destination.balance_paise : 0;
    entry.txn_from_account = is_deposit ? 0 : from_account;
    entry.txn_to_account = is_deposit ? from_account : (is_transfer ? to_account : 0);
    snprintf(entry.type, sizeof(entry.type), "%s", type);
    entry.amount_paise = amount_paise;
    snprintf(entry.actor, sizeof(entry.actor), "%s", actor ? actor : "unknown");
    bank_timestamp(entry.timestamp, sizeof(entry.timestamp));
    if (is_transfer) snprintf(entry.details, sizeof(entry.details), "Transfer to account %d", to_account);
    else if (is_deposit) snprintf(entry.details, sizeof(entry.details), "Cash deposit");
    else snprintf(entry.details, sizeof(entry.details), "Cash withdrawal");
    bank_sanitize_text(entry.details);
    entry.loan_id = 0;
    snprintf(entry.loan_reviewed_by, sizeof(entry.loan_reviewed_by), "-");
    snprintf(entry.loan_note, sizeof(entry.loan_note), "-");

    /* WAL PREPARED must be durable before touching an account or transaction row. */
    if (journal_append_state(journal_fd, &entry, "PREPARED", 1, err, errcap) != 0) goto done;
    maybe_failpoint("after_prepare");

    if (serialize_account(&source, source_line, sizeof(source_line)) != 0 ||
        write_record_locked(fd, source_off, source_line) != 0 || fdatasync(fd) != 0)
        storage_fatal_after_prepare("source account write/sync failed");
    maybe_failpoint("after_account1");

    if (is_transfer) {
        if (serialize_account(&destination, destination_line, sizeof(destination_line)) != 0 ||
            write_record_locked(fd, destination_off, destination_line) != 0 || fdatasync(fd) != 0)
            storage_fatal_after_prepare("destination account write/sync failed");
        maybe_failpoint("after_account2");
    }
    if (append_transaction_once(&entry, err, errcap) != 0)
        storage_fatal_after_prepare("transaction-history append failed");
    maybe_failpoint("after_transaction");
    if (journal_append_state(journal_fd, &entry, "COMMITTED", 0, err, errcap) != 0)
        storage_fatal_after_prepare("could not append COMMITTED journal marker");
    result = 0;

done:
    if (second_locked) (void)lock_region(fd, F_UNLCK, second_lock_off, BANK_RECORD_SIZE);
    if (first_locked) (void)lock_region(fd, F_UNLCK, first_lock_off, BANK_RECORD_SIZE);
    if (fd >= 0) close(fd);
    if (account_mutex_locked) pthread_mutex_unlock(&table_locks[T_ACCOUNTS]);
    end_financial_transaction(journal_fd);
    return result;
}

int store_get_transactions(int account_id, Transaction **items, size_t *count) {
    if (!items || !count) return -1;
    *items = NULL; *count = 0;
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t n = 0;
    if (table_load_rows(T_TRANSACTIONS, &rows, &n) != 0) return -1;
    Transaction *result = n ? calloc(n, sizeof(*result)) : NULL;
    if (n && !result) { free(rows); return -1; }
    size_t used = 0;
    for (size_t i = 0; i < n; ++i) {
        char copy[BANK_RECORD_SIZE];
        memcpy(copy, rows[i], sizeof(copy));
        Transaction t;
        if (parse_transaction(copy, &t) == 0 &&
            (account_id <= 0 || t.from_account == account_id || t.to_account == account_id))
            result[used++] = t;
    }
    free(rows);
    *items = result; *count = used;
    return 0;
}

int store_get_accounts(Account **items, size_t *count) {
    if (!items || !count) return -1;
    *items = NULL; *count = 0;
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t n = 0;
    if (table_load_rows(T_ACCOUNTS, &rows, &n) != 0) return -1;
    Account *result = n ? calloc(n, sizeof(*result)) : NULL;
    if (n && !result) { free(rows); return -1; }
    size_t used = 0;
    for (size_t i = 0; i < n; ++i) {
        char copy[BANK_RECORD_SIZE]; memcpy(copy, rows[i], sizeof(copy));
        Account a;
        if (parse_account(copy, &a) == 0) result[used++] = a;
    }
    free(rows);
    *items = result; *count = used;
    return 0;
}

int store_create_loan(int account_id, const char *applicant,
                      long long amount_paise, int *loan_id,
                      char *err, size_t errcap) {
    Account a;
    if (store_find_account(account_id, &a) != 0 || !a.active) {
        set_error(err, errcap, "A valid active account is required to apply for a loan.");
        return -1;
    }
    if (amount_paise <= 0) {
        set_error(err, errcap, "Loan amount must be greater than zero.");
        return -1;
    }
    Loan l;
    memset(&l, 0, sizeof(l));
    l.account_id = account_id;
    snprintf(l.applicant, sizeof(l.applicant), "%s", applicant);
    l.amount_paise = amount_paise;
    snprintf(l.status, sizeof(l.status), "PENDING");
    snprintf(l.assigned_to, sizeof(l.assigned_to), "-");
    snprintf(l.reviewed_by, sizeof(l.reviewed_by), "-");
    snprintf(l.note, sizeof(l.note), "Loan application submitted");
    bank_timestamp(l.created_at, sizeof(l.created_at));
    if (add_loan_record(&l) != 0) {
        set_error(err, errcap, "Could not save the loan application.");
        return -1;
    }
    if (loan_id) *loan_id = l.id;
    return 0;
}

int store_get_loans(Loan **items, size_t *count) {
    if (!items || !count) return -1;
    *items = NULL; *count = 0;
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t n = 0;
    if (table_load_rows(T_LOANS, &rows, &n) != 0) return -1;
    Loan *result = n ? calloc(n, sizeof(*result)) : NULL;
    if (n && !result) { free(rows); return -1; }
    size_t used = 0;
    for (size_t i = 0; i < n; ++i) {
        char copy[BANK_RECORD_SIZE]; memcpy(copy, rows[i], sizeof(copy));
        Loan l;
        if (parse_loan(copy, &l) == 0) result[used++] = l;
    }
    free(rows);
    *items = result; *count = used;
    return 0;
}

int store_assign_loan(int loan_id, const char *employee_username,
                      const char *manager_username, char *err, size_t errcap) {
    User employee;
    if (store_find_user(employee_username, &employee) != 0 ||
        strcmp(employee.role, "EMPLOYEE") != 0 || !employee.active) {
        set_error(err, errcap, "The assigned username must be an active employee.");
        return -1;
    }
    int fd = -1, result = -1;
    off_t off;
    char row[BANK_RECORD_SIZE], line[BANK_RECORD_SIZE];
    Loan l;
    pthread_mutex_lock(&table_locks[T_LOANS]);
    fd = open_table(T_LOANS, O_RDWR);
    if (fd < 0) goto done;
    if (find_offset_id_locked(T_LOANS, fd, loan_id, &off) != 0) {
        set_error(err, errcap, "Loan %d was not found.", loan_id);
        goto done;
    }
    if (lock_region(fd, F_WRLCK, off, BANK_RECORD_SIZE) != 0) goto done;
    if (pread_full(fd, row, sizeof(row), off) != 0 || parse_loan(row, &l) != 0) {
        (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);
        goto done;
    }
    if (strcmp(l.status, "PENDING") != 0 && strcmp(l.status, "ASSIGNED") != 0) {
        set_error(err, errcap, "Only pending or assigned loans can be assigned.");
    } else {
        snprintf(l.status, sizeof(l.status), "ASSIGNED");
        snprintf(l.assigned_to, sizeof(l.assigned_to), "%s", employee_username);
        snprintf(l.reviewed_by, sizeof(l.reviewed_by), "%s", manager_username);
        snprintf(l.note, sizeof(l.note), "Assigned by manager %s", manager_username);
        if (serialize_loan(&l, line, sizeof(line)) == 0 &&
            write_record_locked(fd, off, line) == 0 && fdatasync(fd) == 0) {
            result = 0;
        } else set_error(err, errcap, "Could not durably update the loan assignment: %s", strerror(errno));
    }
    (void)lock_region(fd, F_UNLCK, off, BANK_RECORD_SIZE);

done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&table_locks[T_LOANS]);
    return result;
}

int store_process_loan(int loan_id, const char *employee_username,
                       int approve, char *err, size_t errcap) {
    User employee;
    if (store_find_user(employee_username, &employee) != 0 ||
        strcmp(employee.role, "EMPLOYEE") != 0 || !employee.active) {
        set_error(err, errcap, "An active employee account is required to process a loan.");
        return -1;
    }

    int journal_fd = -1, accounts_fd = -1, loans_fd = -1, result = -1;
    int accounts_mutex_locked = 0, loans_mutex_locked = 0;
    int account_locked = 0, loan_locked = 0;
    off_t account_off = -1, loan_off = -1;
    char account_row[BANK_RECORD_SIZE], loan_row[BANK_RECORD_SIZE];
    char line[BANK_RECORD_SIZE];
    Account account;
    Loan loan, observed_loan;
    JournalEntry entry;

    if (begin_financial_transaction(&journal_fd, err, errcap) != 0) return -1;
    /* Global order: journal -> accounts table/record -> loans table/record.
     * Re-read the loan after taking its write lock to validate the assignment. */
    pthread_mutex_lock(&table_locks[T_ACCOUNTS]);
    accounts_mutex_locked = 1;
    accounts_fd = open_table(T_ACCOUNTS, O_RDWR);
    if (accounts_fd < 0) {
        set_error(err, errcap, "Could not open accounts.db: %s", strerror(errno));
        goto done;
    }
    pthread_mutex_lock(&table_locks[T_LOANS]);
    loans_mutex_locked = 1;
    loans_fd = open_table(T_LOANS, O_RDWR);
    if (loans_fd < 0) {
        set_error(err, errcap, "Could not open loans.db: %s", strerror(errno));
        goto done;
    }
    if (find_offset_id_locked(T_LOANS, loans_fd, loan_id, &loan_off) != 0) {
        set_error(err, errcap, "Loan %d was not found.", loan_id);
        goto done;
    }
    /* First read only to learn the linked account ID; this lock is released. */
    if (read_record_locked(loans_fd, loan_off, F_RDLCK, loan_row) != 0 ||
        parse_loan(loan_row, &observed_loan) != 0 || observed_loan.id != loan_id) {
        set_error(err, errcap, "Could not read loan #%d.", loan_id);
        goto done;
    }
    if (strcmp(observed_loan.status, "ASSIGNED") != 0 ||
        strcmp(observed_loan.assigned_to, employee_username) != 0) {
        set_error(err, errcap, "This loan is not pending under your employee account.");
        goto done;
    }

    if (!approve) {
        if (lock_region(loans_fd, F_WRLCK, loan_off, BANK_RECORD_SIZE) != 0) {
            set_error(err, errcap, "Could not lock loan #%d.", loan_id);
            goto done;
        }
        loan_locked = 1;
        if (pread_full(loans_fd, loan_row, sizeof(loan_row), loan_off) != 0 ||
            parse_loan(loan_row, &loan) != 0 || loan.id != loan_id ||
            strcmp(loan.status, "ASSIGNED") != 0 ||
            strcmp(loan.assigned_to, employee_username) != 0) {
            set_error(err, errcap, "Loan assignment changed; reload the assigned-loan list.");
            goto done;
        }
        snprintf(loan.status, sizeof(loan.status), "REJECTED");
        snprintf(loan.reviewed_by, sizeof(loan.reviewed_by), "%s", employee_username);
        snprintf(loan.note, sizeof(loan.note), "Rejected by %s", employee_username);
        if (serialize_loan(&loan, line, sizeof(line)) != 0 ||
            write_record_locked(loans_fd, loan_off, line) != 0 || fdatasync(loans_fd) != 0) {
            set_error(err, errcap, "Could not durably save the loan rejection: %s", strerror(errno));
            goto done;
        }
        result = 0;
        goto done;
    }

    if (find_offset_id_locked(T_ACCOUNTS, accounts_fd, observed_loan.account_id, &account_off) != 0) {
        set_error(err, errcap, "Loan applicant account does not exist.");
        goto done;
    }
    /* Lock account before loan to keep a stable lock hierarchy. */
    if (lock_region(accounts_fd, F_WRLCK, account_off, BANK_RECORD_SIZE) != 0) {
        set_error(err, errcap, "Could not lock the applicant account.");
        goto done;
    }
    account_locked = 1;
    if (lock_region(loans_fd, F_WRLCK, loan_off, BANK_RECORD_SIZE) != 0) {
        set_error(err, errcap, "Could not lock loan #%d.", loan_id);
        goto done;
    }
    loan_locked = 1;
    if (pread_full(loans_fd, loan_row, sizeof(loan_row), loan_off) != 0 ||
        parse_loan(loan_row, &loan) != 0 || loan.id != loan_id ||
        loan.account_id != observed_loan.account_id ||
        strcmp(loan.status, "ASSIGNED") != 0 ||
        strcmp(loan.assigned_to, employee_username) != 0) {
        set_error(err, errcap, "Loan assignment changed; reload the assigned-loan list.");
        goto done;
    }
    if (pread_full(accounts_fd, account_row, sizeof(account_row), account_off) != 0 ||
        parse_account(account_row, &account) != 0 || account.id != loan.account_id) {
        set_error(err, errcap, "Could not read the applicant account.");
        goto done;
    }
    if (!account.active) {
        set_error(err, errcap, "The applicant account is inactive.");
        goto done;
    }
    if (LLONG_MAX - account.balance_paise < loan.amount_paise) {
        set_error(err, errcap, "Loan approval would overflow the account balance.");
        goto done;
    }
    account.balance_paise += loan.amount_paise;

    memset(&entry, 0, sizeof(entry));
    entry.account1_id = loan.account_id;
    entry.account1_balance_after = account.balance_paise;
    entry.account2_id = 0;
    entry.txn_from_account = 0;
    entry.txn_to_account = loan.account_id;
    snprintf(entry.type, sizeof(entry.type), "LOAN_APPROVED");
    entry.amount_paise = loan.amount_paise;
    snprintf(entry.actor, sizeof(entry.actor), "%s", employee_username);
    bank_timestamp(entry.timestamp, sizeof(entry.timestamp));
    snprintf(entry.details, sizeof(entry.details), "Approved loan credited");
    entry.loan_id = loan.id;
    snprintf(entry.loan_reviewed_by, sizeof(entry.loan_reviewed_by), "%s", employee_username);
    snprintf(entry.loan_note, sizeof(entry.loan_note), "Approved and credited by %s", employee_username);
    bank_sanitize_text(entry.details);
    bank_sanitize_text(entry.loan_note);

    if (journal_append_state(journal_fd, &entry, "PREPARED", 1, err, errcap) != 0) goto done;
    maybe_failpoint("after_prepare");
    if (serialize_account(&account, line, sizeof(line)) != 0 ||
        write_record_locked(accounts_fd, account_off, line) != 0 || fdatasync(accounts_fd) != 0)
        storage_fatal_after_prepare("loan account credit write/sync failed");
    maybe_failpoint("after_account1");
    if (append_transaction_once(&entry, err, errcap) != 0)
        storage_fatal_after_prepare("loan transaction-history append failed");
    maybe_failpoint("after_transaction");
    snprintf(loan.status, sizeof(loan.status), "APPROVED");
    snprintf(loan.reviewed_by, sizeof(loan.reviewed_by), "%s", entry.loan_reviewed_by);
    snprintf(loan.note, sizeof(loan.note), "%s", entry.loan_note);
    if (serialize_loan(&loan, line, sizeof(line)) != 0 ||
        write_record_locked(loans_fd, loan_off, line) != 0 || fdatasync(loans_fd) != 0)
        storage_fatal_after_prepare("loan approval status write/sync failed");
    maybe_failpoint("after_loan");
    if (journal_append_state(journal_fd, &entry, "COMMITTED", 0, err, errcap) != 0)
        storage_fatal_after_prepare("could not append loan COMMITTED journal marker");
    result = 0;

done:
    if (loan_locked) (void)lock_region(loans_fd, F_UNLCK, loan_off, BANK_RECORD_SIZE);
    if (account_locked) (void)lock_region(accounts_fd, F_UNLCK, account_off, BANK_RECORD_SIZE);
    if (loans_fd >= 0) close(loans_fd);
    if (loans_mutex_locked) pthread_mutex_unlock(&table_locks[T_LOANS]);
    if (accounts_fd >= 0) close(accounts_fd);
    if (accounts_mutex_locked) pthread_mutex_unlock(&table_locks[T_ACCOUNTS]);
    end_financial_transaction(journal_fd);
    return result;
}

int store_add_feedback(const char *username, const char *message,
                       char *err, size_t errcap) {
    if (!message || !*message) {
        set_error(err, errcap, "Feedback cannot be empty.");
        return -1;
    }
    Feedback fb;
    memset(&fb, 0, sizeof(fb));
    snprintf(fb.username, sizeof(fb.username), "%s", username);
    snprintf(fb.message, sizeof(fb.message), "%s", message);
    bank_sanitize_text(fb.message);
    bank_timestamp(fb.timestamp, sizeof(fb.timestamp));
    if (add_feedback_record(&fb) != 0) {
        set_error(err, errcap, "Could not save feedback.");
        return -1;
    }
    return 0;
}

int store_get_feedbacks(Feedback **items, size_t *count) {
    if (!items || !count) return -1;
    *items = NULL; *count = 0;
    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t n = 0;
    if (table_load_rows(T_FEEDBACK, &rows, &n) != 0) return -1;
    Feedback *result = n ? calloc(n, sizeof(*result)) : NULL;
    if (n && !result) { free(rows); return -1; }
    size_t used = 0;
    for (size_t i = 0; i < n; ++i) {
        char copy[BANK_RECORD_SIZE]; memcpy(copy, rows[i], sizeof(copy));
        Feedback fb;
        if (parse_feedback(copy, &fb) == 0) result[used++] = fb;
    }
    free(rows);
    *items = result; *count = used;
    return 0;
}

int store_init(const char *data_dir, char *err, size_t errcap) {
    if (data_dir && *data_dir) {
        if (strlen(data_dir) >= sizeof(g_data_dir)) {
            set_error(err, errcap, "Data directory path is too long.");
            return -1;
        }
        snprintf(g_data_dir, sizeof(g_data_dir), "%s", data_dir);
    }
    if (mkdir(g_data_dir, 0700) != 0 && errno != EEXIST) {
        set_error(err, errcap, "Could not create data directory '%s': %s", g_data_dir, strerror(errno));
        return -1;
    }
    struct stat dst;
    if (stat(g_data_dir, &dst) != 0 || !S_ISDIR(dst.st_mode)) {
        set_error(err, errcap, "Data path '%s' is not a directory.", g_data_dir);
        return -1;
    }
    for (int i = 0; i < T_COUNT; ++i) {
        int fd = open_table((Table)i, O_RDWR | O_CREAT);
        if (fd < 0) {
            set_error(err, errcap, "Could not open %s: %s", table_names[i], strerror(errno));
            return -1;
        }
        if (close(fd) != 0) {
            set_error(err, errcap, "Could not close %s after initialization: %s", table_names[i], strerror(errno));
            return -1;
        }
    }
    /* Persist newly-created database directory entries as well as file contents. */
    int dirfd = open(g_data_dir, O_RDONLY);
    if (dirfd < 0 || fsync(dirfd) != 0) {
        int saved_errno = errno;
        if (dirfd >= 0) close(dirfd);
        set_error(err, errcap, "Could not sync the data directory: %s", strerror(saved_errno));
        return -1;
    }
    if (close(dirfd) != 0) {
        set_error(err, errcap, "Could not close the data directory: %s", strerror(errno));
        return -1;
    }

    /* Recover all durable PREPARED transactions before opening the server to clients. */
    if (recover_journal_at_startup(err, errcap) != 0) return -1;

    char (*rows)[BANK_RECORD_SIZE] = NULL;
    size_t count = 0;
    if (table_load_rows(T_USERS, &rows, &count) != 0) {
        set_error(err, errcap, "Could not read users file.");
        return -1;
    }
    free(rows);
    if (count == 0) {
        const char *names[] = {"admin", "manager", "employee"};
        const char *passwords[] = {"Admin@123", "Manager@123", "Employee@123"};
        const char *roles[] = {"ADMIN", "MANAGER", "EMPLOYEE"};
        const char *fullnames[] = {"System Administrator", "Bank Manager", "Bank Employee"};
        for (int i = 0; i < 3; ++i) {
            User u;
            memset(&u, 0, sizeof(u));
            snprintf(u.username, sizeof(u.username), "%s", names[i]);
            snprintf(u.role, sizeof(u.role), "%s", roles[i]);
            snprintf(u.fullname, sizeof(u.fullname), "%s", fullnames[i]);
            u.active = 1;
            u.account_id = 0;
            if (make_password_hash(passwords[i], u.salt_hex, u.hash_hex) != 0 || add_user_record(&u) != 0) {
                set_error(err, errcap, "Could not create default staff accounts.");
                return -1;
            }
        }
        fprintf(stderr, "First-run staff credentials created (change these passwords):\n"
                        "  admin / Admin@123\n  manager / Manager@123\n  employee / Employee@123\n");
    }
    return 0;
}
