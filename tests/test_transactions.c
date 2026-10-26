#define _POSIX_C_SOURCE 200809L
#include "../bank.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, " (line %d)\n", __LINE__); \
        return 1; \
    } \
} while (0)

typedef struct {
    int from;
    int to;
    int loops;
    const char *actor;
    int failures;
} Worker;

static char data_dir[256];
static int alice_account;
static int bob_account;

static long long balance_of(int account_id) {
    Account a;
    if (store_find_account(account_id, &a) != 0) return -1;
    return a.balance_paise;
}

static int total_transaction_count(void) {
    Transaction *items = NULL;
    size_t count = 0;
    if (store_get_transactions(0, &items, &count) != 0) return -1;
    free(items);
    return (int)count;
}

static int count_type_amount(const char *type, long long amount) {
    Transaction *items = NULL;
    size_t count = 0;
    if (store_get_transactions(0, &items, &count) != 0) return -1;
    int matches = 0;
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(items[i].type, type) == 0 && items[i].amount_paise == amount) matches++;
    }
    free(items);
    return matches;
}

static void *transfer_worker(void *arg) {
    Worker *w = arg;
    for (int i = 0; i < w->loops; ++i) {
        char err[256] = {0};
        if (store_money_action(w->from, w->to, "TRANSFER", 1, w->actor,
                               err, sizeof(err)) != 0) {
            fprintf(stderr, "concurrent transfer failed: %s\n", err);
            __sync_fetch_and_add(&w->failures, 1);
            break;
        }
    }
    return NULL;
}

static void process_transfer_loop(int from, int to, int loops, const char *actor) {
    for (int i = 0; i < loops; ++i) {
        char err[256] = {0};
        if (store_money_action(from, to, "TRANSFER", 1, actor, err, sizeof(err)) != 0) {
            dprintf(STDERR_FILENO, "cross-process transfer failed: %s\n", err);
            _exit(20);
        }
    }
    _exit(0);
}

static int expect_child_crash(void (*operation)(void), const char *description) {
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork for %s failed: %s\n", description, strerror(errno));
        return -1;
    }
    if (child == 0) {
        operation();
        _exit(3); /* Operation should terminate at the injected crash point. */
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 86) {
        fprintf(stderr, "%s: expected test crash exit 86, got status=0x%x\n", description, status);
        return -1;
    }
    return 0;
}

static void crash_deposit_after_prepare(void) {
    char err[256] = {0};
    setenv("BANK_FAILPOINT", "after_prepare", 1);
    (void)store_money_action(alice_account, 0, "DEPOSIT", 12345,
                             "alice_test", err, sizeof(err));
}

static void crash_transfer_after_first_account_write(void) {
    char err[256] = {0};
    setenv("BANK_FAILPOINT", "after_account1", 1);
    (void)store_money_action(alice_account, bob_account, "TRANSFER", 5000,
                             "alice_test", err, sizeof(err));
}

static void crash_transfer_after_both_account_writes(void) {
    char err[256] = {0};
    setenv("BANK_FAILPOINT", "after_account2", 1);
    (void)store_money_action(alice_account, bob_account, "TRANSFER", 7000,
                             "alice_test", err, sizeof(err));
}

static int recovery_loan_id;
static void crash_loan_after_transaction_row(void) {
    char err[256] = {0};
    setenv("BANK_FAILPOINT", "after_transaction", 1);
    (void)store_process_loan(recovery_loan_id, "employee", 1, err, sizeof(err));
}

static void crash_loan_after_status_before_commit(void) {
    char err[256] = {0};
    setenv("BANK_FAILPOINT", "after_loan", 1);
    (void)store_process_loan(recovery_loan_id, "employee", 1, err, sizeof(err));
}

static void cleanup_data_dir(void) {
    const char *files[] = {"users.db", "accounts.db", "transactions.db", "loans.db",
                           "feedback.db", "journal.db"};
    char path[512];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        snprintf(path, sizeof(path), "%s/%s", data_dir, files[i]);
        (void)unlink(path);
    }
    (void)rmdir(data_dir);
}

int main(void) {
    char pattern[] = "/tmp/eg301-wal-test-XXXXXX";
    char err[512] = {0};
    char *dir = mkdtemp(pattern);
    CHECK(dir != NULL, "mkdtemp failed: %s", strerror(errno));
    snprintf(data_dir, sizeof(data_dir), "%s", dir);

    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "initial store_init: %s", err);
    User alice, bob;
    CHECK(store_register_customer("alice_test", "AliceSecure123", "Alice Test", 0, 0,
                                  &alice, err, sizeof(err)) == 0,
          "register Alice: %s", err);
    CHECK(store_register_customer("bob_test", "BobSecure12345", "Bob Test", 0, 0,
                                  &bob, err, sizeof(err)) == 0,
          "register Bob: %s", err);
    alice_account = alice.account_id;
    bob_account = bob.account_id;

    CHECK(store_money_action(alice_account, 0, "DEPOSIT", 1000000, "alice_test",
                             err, sizeof(err)) == 0, "seed Alice: %s", err);
    CHECK(store_money_action(bob_account, 0, "DEPOSIT", 1000000, "bob_test",
                             err, sizeof(err)) == 0, "seed Bob: %s", err);
    long long initial_total = balance_of(alice_account) + balance_of(bob_account);

    /* Four threads concurrently transfer tiny amounts in opposing directions. */
    pthread_t threads[4];
    Worker workers[4] = {
        {alice_account, bob_account, 50, "alice_test", 0},
        {alice_account, bob_account, 50, "alice_test", 0},
        {bob_account, alice_account, 50, "bob_test", 0},
        {bob_account, alice_account, 50, "bob_test", 0}
    };
    for (int i = 0; i < 4; ++i)
        CHECK(pthread_create(&threads[i], NULL, transfer_worker, &workers[i]) == 0,
              "pthread_create failed for worker %d", i);
    for (int i = 0; i < 4; ++i) pthread_join(threads[i], NULL);
    for (int i = 0; i < 4; ++i) CHECK(workers[i].failures == 0, "concurrent worker %d failed", i);
    CHECK(balance_of(alice_account) + balance_of(bob_account) == initial_total,
          "total balance changed after concurrent transfers");
    printf("PASS: 200 concurrent transfers conserve total balance across pthreads.\n");

    /* Separate processes have independent pthread mutexes; journal.db's fcntl
     * lock must serialize their financial commits too. */
    pid_t child_a = fork();
    CHECK(child_a >= 0, "first cross-process fork failed: %s", strerror(errno));
    if (child_a == 0) process_transfer_loop(alice_account, bob_account, 25, "alice_test");
    pid_t child_b = fork();
    CHECK(child_b >= 0, "second cross-process fork failed: %s", strerror(errno));
    if (child_b == 0) process_transfer_loop(bob_account, alice_account, 25, "bob_test");
    int status_a = 0, status_b = 0;
    CHECK(waitpid(child_a, &status_a, 0) == child_a && WIFEXITED(status_a) && WEXITSTATUS(status_a) == 0,
          "first cross-process worker failed (status=0x%x)", status_a);
    CHECK(waitpid(child_b, &status_b, 0) == child_b && WIFEXITED(status_b) && WEXITSTATUS(status_b) == 0,
          "second cross-process worker failed (status=0x%x)", status_b);
    CHECK(balance_of(alice_account) + balance_of(bob_account) == initial_total,
          "total balance changed after cross-process transfers");
    printf("PASS: 50 cross-process transfers preserve total balance using fcntl journal locking.\n");

    long long alice_before_prepare_crash = balance_of(alice_account);
    int tx_before_prepare_crash = total_transaction_count();
    CHECK(expect_child_crash(crash_deposit_after_prepare, "deposit prepare crash test") == 0,
          "deposit prepare failpoint did not simulate a crash");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "startup prepare recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_prepare_crash + 12345,
          "prepared deposit did not recover to its intended balance");
    CHECK(total_transaction_count() == tx_before_prepare_crash + 1 &&
          count_type_amount("DEPOSIT", 12345) == 1,
          "prepared deposit did not produce exactly one transaction row");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "repeat prepare recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_prepare_crash + 12345 &&
          total_transaction_count() == tx_before_prepare_crash + 1,
          "prepared deposit applied more than once on repeated recovery");
    printf("PASS: crash immediately after PREPARED journal record recovers once.\n");

    long long alice_before_crash = balance_of(alice_account);
    long long bob_before_crash = balance_of(bob_account);
    int tx_before_crash = total_transaction_count();
    CHECK(expect_child_crash(crash_transfer_after_first_account_write, "transfer crash test") == 0,
          "transfer failpoint did not simulate a crash");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "startup transfer recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_crash - 5000,
          "source balance not recovered after transfer crash");
    CHECK(balance_of(bob_account) == bob_before_crash + 5000,
          "destination balance not recovered after transfer crash");
    CHECK(total_transaction_count() == tx_before_crash + 1,
          "recovered transfer transaction row count is not exactly one");
    CHECK(count_type_amount("TRANSFER", 5000) == 1,
          "recovered transfer was missing or duplicated");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "second recovery pass: %s", err);
    CHECK(balance_of(alice_account) == alice_before_crash - 5000 &&
          balance_of(bob_account) == bob_before_crash + 5000,
          "second recovery pass applied transfer twice");
    CHECK(total_transaction_count() == tx_before_crash + 1,
          "second recovery pass duplicated transaction history");
    printf("PASS: transfer crash recovery is idempotent and transaction history is exactly-once.\n");

    long long alice_before_second_crash = balance_of(alice_account);
    long long bob_before_second_crash = balance_of(bob_account);
    int tx_before_second_crash = total_transaction_count();
    CHECK(expect_child_crash(crash_transfer_after_both_account_writes, "both-account transfer crash test") == 0,
          "after-account2 failpoint did not simulate a crash");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "startup both-account recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_second_crash - 7000 &&
          balance_of(bob_account) == bob_before_second_crash + 7000,
          "transfer recovery after both balance writes failed");
    CHECK(total_transaction_count() == tx_before_second_crash + 1 &&
          count_type_amount("TRANSFER", 7000) == 1,
          "recovered transfer after both account writes was missing/duplicated");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "second both-account recovery pass: %s", err);
    CHECK(balance_of(alice_account) == alice_before_second_crash - 7000 &&
          balance_of(bob_account) == bob_before_second_crash + 7000 &&
          total_transaction_count() == tx_before_second_crash + 1,
          "repeat recovery reapplied transfer after both account writes");
    printf("PASS: crash after both balance writes recovers without lost/duplicate rows.\n");

    int loan_id = 0;
    recovery_loan_id = 0;
    CHECK(store_create_loan(alice_account, "alice_test", 20000, &loan_id,
                            err, sizeof(err)) == 0, "create loan: %s", err);
    CHECK(store_assign_loan(loan_id, "employee", "manager", err, sizeof(err)) == 0,
          "assign loan: %s", err);
    recovery_loan_id = loan_id;
    long long alice_before_loan = balance_of(alice_account);
    int tx_before_loan = total_transaction_count();
    CHECK(expect_child_crash(crash_loan_after_transaction_row, "loan approval crash test") == 0,
          "loan failpoint did not simulate a crash");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "startup loan recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_loan + 20000,
          "loan credit not recovered or credited more than once");
    Loan *loans = NULL;
    size_t loan_count = 0;
    CHECK(store_get_loans(&loans, &loan_count) == 0, "could not read loans after recovery");
    int found_approved = 0;
    for (size_t i = 0; i < loan_count; ++i)
        if (loans[i].id == loan_id && strcmp(loans[i].status, "APPROVED") == 0) found_approved = 1;
    free(loans);
    CHECK(found_approved, "loan status was not recovered to APPROVED");
    CHECK(total_transaction_count() == tx_before_loan + 1,
          "loan approval did not produce exactly one history row");
    CHECK(count_type_amount("LOAN_APPROVED", 20000) == 1,
          "loan approval transaction missing or duplicated");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "second loan recovery pass: %s", err);
    CHECK(balance_of(alice_account) == alice_before_loan + 20000,
          "repeated startup recovery credited loan twice");
    CHECK(total_transaction_count() == tx_before_loan + 1,
          "repeated startup recovery duplicated loan transaction");
    printf("PASS: loan crash before status update restores approval and credits exactly once.\n");

    int second_loan_id = 0;
    CHECK(store_create_loan(alice_account, "alice_test", 35000, &second_loan_id,
                            err, sizeof(err)) == 0, "create second loan: %s", err);
    CHECK(store_assign_loan(second_loan_id, "employee", "manager", err, sizeof(err)) == 0,
          "assign second loan: %s", err);
    recovery_loan_id = second_loan_id;
    long long alice_before_second_loan = balance_of(alice_account);
    int tx_before_second_loan = total_transaction_count();
    CHECK(expect_child_crash(crash_loan_after_status_before_commit, "loan status-before-commit crash test") == 0,
          "loan status failpoint did not simulate a crash");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "startup post-status loan recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_second_loan + 35000,
          "recovery reapplied a loan credit after status was already APPROVED");
    CHECK(total_transaction_count() == tx_before_second_loan + 1 &&
          count_type_amount("LOAN_APPROVED", 35000) == 1,
          "post-status loan recovery duplicated/missed transaction history");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "repeat post-status loan recovery: %s", err);
    CHECK(balance_of(alice_account) == alice_before_second_loan + 35000 &&
          total_transaction_count() == tx_before_second_loan + 1,
          "repeated post-status loan recovery credited twice");
    char retry_error[256] = {0};
    CHECK(store_process_loan(second_loan_id, "employee", 1, retry_error, sizeof(retry_error)) != 0,
          "retrying an already-approved loan should be rejected");
    CHECK(balance_of(alice_account) == alice_before_second_loan + 35000 &&
          total_transaction_count() == tx_before_second_loan + 1,
          "retry of an approved loan changed balance or duplicated its transaction");
    printf("PASS: crash after loan status update and explicit approval retry do not double-credit.\n");

    /* A crash while appending a journal row may leave an incomplete fixed-size
     * tail. Startup should truncate just that tail and retain committed state. */
    long long alice_before_torn_tail = balance_of(alice_account);
    char journal_path[512];
    snprintf(journal_path, sizeof(journal_path), "%s/journal.db", data_dir);
    int journal_file = open(journal_path, O_WRONLY | O_APPEND);
    CHECK(journal_file >= 0, "could not open journal for torn-tail test: %s", strerror(errno));
    const char partial[] = "simulated-torn-journal";
    ssize_t wrote = write(journal_file, partial, sizeof(partial) - 1);
    CHECK(wrote == (ssize_t)(sizeof(partial) - 1), "could not append simulated torn tail");
    CHECK(fdatasync(journal_file) == 0, "could not sync simulated torn tail: %s", strerror(errno));
    CHECK(close(journal_file) == 0, "could not close journal after torn-tail test");
    CHECK(store_init(data_dir, err, sizeof(err)) == 0, "repair incomplete journal tail: %s", err);
    struct stat journal_stat;
    CHECK(stat(journal_path, &journal_stat) == 0 && journal_stat.st_size % 1024 == 0,
          "startup did not truncate the incomplete journal tail");
    CHECK(balance_of(alice_account) == alice_before_torn_tail,
          "tail repair changed an already-committed account balance");
    printf("PASS: startup repairs a torn final journal row without changing committed balances.\n");

    cleanup_data_dir();
    printf("ALL TESTS PASSED.\n");
    return 0;
}
