#ifndef BANK_H
#define BANK_H

#include <stddef.h>
#include <stdint.h>

#define BANK_USERNAME_LEN 32
#define BANK_NAME_LEN 64
#define BANK_ROLE_LEN 16
#define BANK_TYPE_LEN 12
#define BANK_STATUS_LEN 16
#define BANK_TIME_LEN 32
#define BANK_MESSAGE_LEN 256
#define BANK_DETAILS_LEN 128
#define BANK_RECORD_SIZE 1024
#define BANK_DATA_DIR_LEN 512

typedef struct {
    int id;
    char username[BANK_USERNAME_LEN + 1];
    char salt_hex[33];
    char hash_hex[65];
    char role[BANK_ROLE_LEN];
    int active;
    char fullname[BANK_NAME_LEN];
    int account_id;
} User;

typedef struct {
    int id;
    char owner1[BANK_USERNAME_LEN + 1];
    char owner2[BANK_USERNAME_LEN + 1];
    long long balance_paise;
    int active;
    char type[BANK_TYPE_LEN];
} Account;

typedef struct {
    int id;
    int from_account;
    int to_account;
    char type[24];
    long long amount_paise;
    char actor[BANK_USERNAME_LEN + 1];
    char timestamp[BANK_TIME_LEN];
    char details[BANK_DETAILS_LEN];
    /* 0 for legacy transactions; nonzero means this row was created by journal entry id. */
    long long journal_id;
} Transaction;

typedef struct {
    int id;
    int account_id;
    char applicant[BANK_USERNAME_LEN + 1];
    long long amount_paise;
    char status[BANK_STATUS_LEN];
    char assigned_to[BANK_USERNAME_LEN + 1];
    char created_at[BANK_TIME_LEN];
    char reviewed_by[BANK_USERNAME_LEN + 1];
    char note[BANK_DETAILS_LEN];
} Loan;

typedef struct {
    int id;
    char username[BANK_USERNAME_LEN + 1];
    char message[BANK_MESSAGE_LEN];
    char timestamp[BANK_TIME_LEN];
} Feedback;

/* Initializes the text-record data store, creating default staff on first run. */
int store_init(const char *data_dir, char *err, size_t errcap);

/* Authentication and account/user management. */
int store_authenticate(const char *username, const char *password,
                       const char *requested_role, User *out,
                       char *err, size_t errcap);
int store_find_user(const char *username, User *out);
int store_find_account(int account_id, Account *out);
int store_register_customer(const char *username, const char *password,
                            const char *fullname, int is_joint,
                            int joint_account_id, User *created,
                            char *err, size_t errcap);
int store_add_staff(const char *username, const char *password,
                    const char *fullname, const char *role,
                    char *err, size_t errcap);
int store_change_password(const char *username, const char *old_password,
                          const char *new_password, char *err, size_t errcap);
int store_update_fullname(const char *username, const char *fullname,
                          char *err, size_t errcap);
int store_set_account_active(int account_id, int active,
                             char *err, size_t errcap);
int store_modify_account_owner_name(int account_id, const char *fullname,
                                    char *err, size_t errcap);
int store_account_view(int account_id, Account *account, User *owner1,
                       User *owner2);

/* Deposits, withdrawals and transfers are performed while holding write locks. */
int store_money_action(int from_account, int to_account, const char *type,
                       long long amount_paise, const char *actor,
                       char *err, size_t errcap);

/* Transactions, loans, feedback, and list operations. Caller frees returned arrays. */
int store_get_transactions(int account_id, Transaction **items, size_t *count);
int store_get_accounts(Account **items, size_t *count);
int store_create_loan(int account_id, const char *applicant,
                      long long amount_paise, int *loan_id,
                      char *err, size_t errcap);
int store_get_loans(Loan **items, size_t *count);
int store_assign_loan(int loan_id, const char *employee_username,
                      const char *manager_username, char *err, size_t errcap);
int store_process_loan(int loan_id, const char *employee_username,
                       int approve, char *err, size_t errcap);
int store_add_feedback(const char *username, const char *message,
                       char *err, size_t errcap);
int store_get_feedbacks(Feedback **items, size_t *count);

/* Utility helpers shared with the server. */
int bank_parse_money(const char *text, long long *paise_out);
void bank_format_money(long long paise, char *out, size_t outcap);
int bank_valid_username(const char *s);
void bank_sanitize_text(char *s);
void bank_timestamp(char *out, size_t outcap);

#endif
