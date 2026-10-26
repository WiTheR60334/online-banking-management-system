#define _POSIX_C_SOURCE 200809L
#include "bank.h"
#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_BACKLOG 32
#define REQUEST_CAP 8192
#define RESPONSE_CAP 8192
#define SESSION_LIMIT 512

static volatile sig_atomic_t g_running = 1;
static int g_listen_fd = -1;
static pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;
static char active_sessions[SESSION_LIMIT][BANK_USERNAME_LEN + 1];

static void stop_server(int signo) {
    (void)signo;
    /* No SA_RESTART is used, so accept() will return EINTR and the main loop exits. */
    g_running = 0;
}

static int sendf_line(int fd, const char *fmt, ...) {
    char response[RESPONSE_CAP];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(response, sizeof(response), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(response)) return -1;
    return net_send_line(fd, response);
}

static int split_fields(char *line, char **fields, int max_fields) {
    int count = 0;
    char *save = NULL;
    char *token = strtok_r(line, "|", &save);
    while (token && count < max_fields) {
        fields[count++] = token;
        token = strtok_r(NULL, "|", &save);
    }
    return count;
}

static int session_add(const char *username) {
    int result = -1;
    pthread_mutex_lock(&sessions_mutex);
    int empty_slot = -1;
    for (int i = 0; i < SESSION_LIMIT; ++i) {
        if (active_sessions[i][0] == '\0') {
            if (empty_slot < 0) empty_slot = i;
        } else if (strcmp(active_sessions[i], username) == 0) {
            pthread_mutex_unlock(&sessions_mutex);
            return 0;
        }
    }
    if (empty_slot >= 0) {
        snprintf(active_sessions[empty_slot], sizeof(active_sessions[empty_slot]), "%s", username);
        result = 1;
    }
    pthread_mutex_unlock(&sessions_mutex);
    return result;
}

static void session_remove(const char *username) {
    pthread_mutex_lock(&sessions_mutex);
    for (int i = 0; i < SESSION_LIMIT; ++i) {
        if (strcmp(active_sessions[i], username) == 0) {
            active_sessions[i][0] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&sessions_mutex);
}

static int is_customer_role(const char *role) {
    return strcmp(role, "CUSTOMER") == 0 || strcmp(role, "JOINT") == 0;
}

static void format_account_line(const Account *a, char *out, size_t cap) {
    User owner1, owner2;
    memset(&owner1, 0, sizeof(owner1));
    memset(&owner2, 0, sizeof(owner2));
    (void)store_account_view(a->id, NULL, &owner1, &owner2);
    char money[64];
    bank_format_money(a->balance_paise, money, sizeof(money));
    if (strcmp(a->owner2, "-") == 0) {
        snprintf(out, cap,
                 "Account #%d | type=%s | owner=%s (%s) | balance=%s | status=%s",
                 a->id, a->type, a->owner1,
                 owner1.fullname[0] ? owner1.fullname : "name unavailable",
                 money, a->active ? "ACTIVE" : "INACTIVE");
    } else {
        snprintf(out, cap,
                 "Account #%d | type=%s | owner1=%s (%s) | owner2=%s (%s) | balance=%s | status=%s",
                 a->id, a->type, a->owner1,
                 owner1.fullname[0] ? owner1.fullname : "name unavailable",
                 a->owner2, owner2.fullname[0] ? owner2.fullname : "name unavailable",
                 money, a->active ? "ACTIVE" : "INACTIVE");
    }
}

static int send_list_header(int fd, size_t count) {
    return sendf_line(fd, "LIST|%zu", count);
}

static int send_history(int fd, int account_id) {
    Transaction *items = NULL;
    size_t count = 0;
    Account account;
    if (store_find_account(account_id, &account) != 0)
        return sendf_line(fd, "ERR|Account not found.");
    if (store_get_transactions(account_id, &items, &count) != 0)
        return sendf_line(fd, "ERR|Could not read transaction history.");

    char current_balance[64], header[160];
    bank_format_money(account.balance_paise, current_balance, sizeof(current_balance));
    snprintf(header, sizeof(header), "Current balance: %s", current_balance);
    if (sendf_line(fd, "LIST|%zu|%s", count, header) != 0) {
        free(items);
        return -1;
    }

    /* Reconstruct the account's historical running balance from its ledger entries. */
    long long running_balance_paise = 0;
    for (size_t i = 0; i < count; ++i) {
        Transaction *t = &items[i];
        if (t->to_account == account_id) running_balance_paise += t->amount_paise;
        if (t->from_account == account_id) running_balance_paise -= t->amount_paise;

        char amount[64], balance_after[64], line[RESPONSE_CAP];
        bank_format_money(t->amount_paise, amount, sizeof(amount));
        bank_format_money(running_balance_paise, balance_after, sizeof(balance_after));
        snprintf(line, sizeof(line),
                 "#%d | %-14s | amount=%s | balance_after=%s | from=%d to=%d | actor=%s | %s | %s",
                 t->id, t->type, amount, balance_after, t->from_account, t->to_account,
                 t->actor, t->timestamp, t->details);
        if (net_send_line(fd, line) != 0) { free(items); return -1; }
    }
    free(items);
    return net_send_line(fd, "END");
}

static int send_accounts(int fd) {
    Account *items = NULL;
    size_t count = 0;
    if (store_get_accounts(&items, &count) != 0)
        return sendf_line(fd, "ERR|Could not read accounts.");
    if (send_list_header(fd, count) != 0) { free(items); return -1; }
    for (size_t i = 0; i < count; ++i) {
        char line[RESPONSE_CAP];
        format_account_line(&items[i], line, sizeof(line));
        if (net_send_line(fd, line) != 0) { free(items); return -1; }
    }
    free(items);
    return net_send_line(fd, "END");
}

static int send_loans(int fd, const char *role, const char *username) {
    Loan *items = NULL;
    size_t count = 0;
    if (store_get_loans(&items, &count) != 0)
        return sendf_line(fd, "ERR|Could not read loan applications.");
    size_t shown = 0;
    if (strcmp(role, "EMPLOYEE") == 0) {
        for (size_t i = 0; i < count; ++i)
            if (strcmp(items[i].assigned_to, username) == 0) shown++;
    } else shown = count;

    if (send_list_header(fd, shown) != 0) { free(items); return -1; }
    for (size_t i = 0; i < count; ++i) {
        Loan *l = &items[i];
        if (strcmp(role, "EMPLOYEE") == 0 && strcmp(l->assigned_to, username) != 0) continue;
        char amount[64], line[RESPONSE_CAP];
        bank_format_money(l->amount_paise, amount, sizeof(amount));
        const char *assignment = (!l->assigned_to[0] || strcmp(l->assigned_to, "-") == 0)
                                     ? "UNASSIGNED" : l->assigned_to;
        snprintf(line, sizeof(line),
                 "Loan #%d | account=%d | applicant=%s | amount=%s | status=%s | assigned=%s | created=%s | note=%s",
                 l->id, l->account_id, l->applicant, amount, l->status,
                 assignment, l->created_at, l->note);
        if (net_send_line(fd, line) != 0) { free(items); return -1; }
    }
    free(items);
    return net_send_line(fd, "END");
}

static int send_feedbacks(int fd) {
    Feedback *items = NULL;
    size_t count = 0;
    if (store_get_feedbacks(&items, &count) != 0)
        return sendf_line(fd, "ERR|Could not read feedback.");
    if (send_list_header(fd, count) != 0) { free(items); return -1; }
    for (size_t i = 0; i < count; ++i) {
        char line[RESPONSE_CAP];
        snprintf(line, sizeof(line), "Feedback #%d | user=%s | %s | %s",
                 items[i].id, items[i].username, items[i].timestamp, items[i].message);
        if (net_send_line(fd, line) != 0) { free(items); return -1; }
    }
    free(items);
    return net_send_line(fd, "END");
}

static int handle_register(int fd, char **f, int n) {
    if (n != 5 || strcmp(f[4], "SINGLE") != 0)
        return sendf_line(fd, "ERR|Self-registration opens single-owner accounts only. Ask an administrator to add a joint holder.");
    char err[512] = {0};
    User created;
    if (store_register_customer(f[1], f[2], f[3], 0, 0,
                                &created, err, sizeof(err)) != 0)
        return sendf_line(fd, "ERR|%s", err[0] ? err : "Registration failed.");
    return sendf_line(fd, "OK|Account opened successfully. Account number: %d. You can now log in.", created.account_id);
}

static int handle_login(int fd, char **f, int n, User *current, int *logged_in) {
    if (n != 4) return sendf_line(fd, "ERR|Use LOGIN|ROLE|USERNAME|PASSWORD.");
    char role[BANK_ROLE_LEN];
    snprintf(role, sizeof(role), "%s", f[1]);
    for (char *p = role; *p; ++p) {
        if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 'a' + 'A');
    }
    if (strcmp(role, "CUSTOMER") != 0 && strcmp(role, "JOINT") != 0 &&
        strcmp(role, "EMPLOYEE") != 0 && strcmp(role, "MANAGER") != 0 &&
        strcmp(role, "ADMIN") != 0)
        return sendf_line(fd, "ERR|Unknown role.");

    char err[512] = {0};
    User user;
    if (store_authenticate(f[2], f[3], role, &user, err, sizeof(err)) != 0)
        return sendf_line(fd, "ERR|%s", err[0] ? err : "Login failed.");
    int added = session_add(user.username);
    if (added == 0) return sendf_line(fd, "ERR|This user is already logged in from another client.");
    if (added < 0) return sendf_line(fd, "ERR|The server has reached its active-session limit.");
    *current = user;
    *logged_in = 1;
    if (sendf_line(fd, "OK|LOGIN|%s|%s|%d", user.role, user.username, user.account_id) != 0) {
        session_remove(user.username);
        *logged_in = 0;
        return -1;
    }
    fprintf(stderr, "[login] %s (%s) connected\n", user.username, user.role);
    return 0;
}

static int parse_positive_int(const char *text, int *out) {
    if (!text || !*text || !out) return -1;
    char *end = NULL;
    long val = strtol(text, &end, 10);
    if (!end || *end || val <= 0 || val > 2147483647L) return -1;
    *out = (int)val;
    return 0;
}

static int require_role(int fd, const User *u, const char *r1, const char *r2) {
    if (strcmp(u->role, r1) == 0 || (r2 && strcmp(u->role, r2) == 0)) return 1;
    (void)sendf_line(fd, "ERR|Your role is not allowed to perform this operation.");
    return 0;
}

static int handle_command(int fd, User *user, char *request, int *should_logout) {
    char *f[12];
    int n = split_fields(request, f, 12);
    if (n == 0) return sendf_line(fd, "ERR|Empty request.");
    const char *cmd = f[0];
    char err[512] = {0};
    *should_logout = 0;

    if (strcmp(cmd, "LOGOUT") == 0) {
        *should_logout = 1;
        return sendf_line(fd, "OK|Logged out.");
    }
    if (is_customer_role(user->role)) {
        Account active_account;
        if (store_find_account(user->account_id, &active_account) != 0 || !active_account.active)
            return sendf_line(fd, "ERR|Your account is inactive. Banking actions are blocked.");
    }
    if (strcmp(cmd, "CHANGE_PASSWORD") == 0) {
        if (n != 3) return sendf_line(fd, "ERR|Use CHANGE_PASSWORD|CURRENT|NEW.");
        if (store_change_password(user->username, f[1], f[2], err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Password change failed.");
        return sendf_line(fd, "OK|Password changed successfully.");
    }

    if (is_customer_role(user->role)) {
        Account a;
        if (strcmp(cmd, "BALANCE") == 0 && n == 1) {
            if (store_find_account(user->account_id, &a) != 0)
                return sendf_line(fd, "ERR|Could not read account.");
            char money[64]; bank_format_money(a.balance_paise, money, sizeof(money));
            return sendf_line(fd, "OK|Current balance: %s", money);
        }
        if (strcmp(cmd, "VIEW_DETAILS") == 0 && n == 1) {
            Account account; User owner1, owner2;
            if (store_account_view(user->account_id, &account, &owner1, &owner2) != 0)
                return sendf_line(fd, "ERR|Could not read account details.");
            char money[64]; bank_format_money(account.balance_paise, money, sizeof(money));
            if (strcmp(account.owner2, "-") == 0)
                return sendf_line(fd, "OK|Account=%d | Owner=%s (%s) | Type=%s | Balance=%s | Status=%s",
                                  account.id, owner1.username, owner1.fullname, account.type, money,
                                  account.active ? "ACTIVE" : "INACTIVE");
            return sendf_line(fd, "OK|Account=%d | Owner1=%s (%s) | Owner2=%s (%s) | Type=%s | Balance=%s | Status=%s",
                              account.id, owner1.username, owner1.fullname, owner2.username, owner2.fullname,
                              account.type, money, account.active ? "ACTIVE" : "INACTIVE");
        }
        if ((strcmp(cmd, "DEPOSIT") == 0 || strcmp(cmd, "WITHDRAW") == 0) && n == 2) {
            long long amount;
            if (bank_parse_money(f[1], &amount) != 0)
                return sendf_line(fd, "ERR|Enter a positive amount, for example 1250 or 1250.50.");
            const char *type = strcmp(cmd, "DEPOSIT") == 0 ? "DEPOSIT" : "WITHDRAW";
            if (store_money_action(user->account_id, 0, type, amount, user->username,
                                   err, sizeof(err)) != 0)
                return sendf_line(fd, "ERR|%s", err[0] ? err : "Transaction failed.");
            char money[64]; bank_format_money(amount, money, sizeof(money));
            return sendf_line(fd, "OK|%s of %s completed.", type, money);
        }
        if (strcmp(cmd, "TRANSFER") == 0 && n == 3) {
            int destination; long long amount;
            if (parse_positive_int(f[1], &destination) != 0)
                return sendf_line(fd, "ERR|Destination account number must be a positive whole number.");
            if (bank_parse_money(f[2], &amount) != 0)
                return sendf_line(fd, "ERR|Amount must be greater than zero. Enter a value such as 250 or 250.75.");
            if (store_money_action(user->account_id, destination, "TRANSFER", amount,
                                   user->username, err, sizeof(err)) != 0)
                return sendf_line(fd, "ERR|%s", err[0] ? err : "Transfer failed.");
            char money[64]; bank_format_money(amount, money, sizeof(money));
            return sendf_line(fd, "OK|Transferred %s to account %d.", money, destination);
        }
        if (strcmp(cmd, "HISTORY") == 0 && n == 1) return send_history(fd, user->account_id);
        if (strcmp(cmd, "APPLY_LOAN") == 0 && n == 2) {
            long long amount; int loan_id = 0;
            if (bank_parse_money(f[1], &amount) != 0)
                return sendf_line(fd, "ERR|Enter a positive loan amount.");
            if (store_create_loan(user->account_id, user->username, amount, &loan_id,
                                  err, sizeof(err)) != 0)
                return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not apply for loan.");
            return sendf_line(fd, "OK|Loan application submitted. Loan ID: %d.", loan_id);
        }
        if (strcmp(cmd, "FEEDBACK") == 0 && n == 2) {
            if (store_add_feedback(user->username, f[1], err, sizeof(err)) != 0)
                return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not save feedback.");
            return sendf_line(fd, "OK|Feedback saved. Thank you.");
        }
        return sendf_line(fd, "ERR|Unknown customer command.");
    }

    if (strcmp(cmd, "ADD_CUSTOMER") == 0 && n == 4) {
        if (!require_role(fd, user, "EMPLOYEE", "ADMIN")) return 0;
        User created;
        if (store_register_customer(f[1], f[2], f[3], 0, 0, &created, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not add customer.");
        return sendf_line(fd, "OK|Customer created. Account number: %d.", created.account_id);
    }
    if (strcmp(cmd, "MODIFY_CUSTOMER") == 0 && n == 3) {
        if (!require_role(fd, user, "EMPLOYEE", "ADMIN")) return 0;
        User target;
        if (store_find_user(f[1], &target) != 0 ||
            (!is_customer_role(target.role)))
            return sendf_line(fd, "ERR|Target username is not a customer or joint holder.");
        if (store_update_fullname(f[1], f[2], err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not update customer details.");
        return sendf_line(fd, "OK|Customer details updated.");
    }
    if (strcmp(cmd, "HISTORY_ACCOUNT") == 0 && n == 2) {
        if (!require_role(fd, user, "EMPLOYEE", "ADMIN")) return 0;
        int account_id;
        if (parse_positive_int(f[1], &account_id) != 0)
            return sendf_line(fd, "ERR|Invalid account number.");
        Account a;
        if (store_find_account(account_id, &a) != 0)
            return sendf_line(fd, "ERR|Account not found.");
        return send_history(fd, account_id);
    }
    if (strcmp(cmd, "LOANS") == 0 && n == 1) {
        if (strcmp(user->role, "EMPLOYEE") != 0 && strcmp(user->role, "MANAGER") != 0 &&
            strcmp(user->role, "ADMIN") != 0)
            return sendf_line(fd, "ERR|Your role is not allowed to view loans.");
        return send_loans(fd, user->role, user->username);
    }
    if (strcmp(cmd, "PROCESS_LOAN") == 0 && n == 3) {
        if (!require_role(fd, user, "EMPLOYEE", NULL)) return 0;
        int loan_id;
        if (parse_positive_int(f[1], &loan_id) != 0)
            return sendf_line(fd, "ERR|Invalid loan ID.");
        int approve = strcmp(f[2], "APPROVE") == 0;
        if (!approve && strcmp(f[2], "REJECT") != 0)
            return sendf_line(fd, "ERR|Decision must be APPROVE or REJECT.");
        if (store_process_loan(loan_id, user->username, approve, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not process loan.");
        return sendf_line(fd, "OK|Loan #%d %s.", loan_id, approve ? "approved and credited" : "rejected");
    }
    if (strcmp(cmd, "SET_ACCOUNT_STATUS") == 0 && n == 3) {
        if (!require_role(fd, user, "MANAGER", "ADMIN")) return 0;
        int account_id;
        if (parse_positive_int(f[1], &account_id) != 0)
            return sendf_line(fd, "ERR|Invalid account number.");
        int active = strcmp(f[2], "ACTIVE") == 0;
        if (!active && strcmp(f[2], "INACTIVE") != 0)
            return sendf_line(fd, "ERR|Status must be ACTIVE or INACTIVE.");
        if (store_set_account_active(account_id, active, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not update account status.");
        return sendf_line(fd, "OK|Account #%d is now %s.", account_id, active ? "ACTIVE" : "INACTIVE");
    }
    if (strcmp(cmd, "ASSIGN_LOAN") == 0 && n == 3) {
        if (!require_role(fd, user, "MANAGER", "ADMIN")) return 0;
        int loan_id;
        if (parse_positive_int(f[1], &loan_id) != 0)
            return sendf_line(fd, "ERR|Invalid loan ID.");
        if (store_assign_loan(loan_id, f[2], user->username, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not assign loan.");
        return sendf_line(fd, "OK|Loan #%d assigned to %s.", loan_id, f[2]);
    }
    if (strcmp(cmd, "FEEDBACKS") == 0 && n == 1) {
        if (!require_role(fd, user, "MANAGER", "ADMIN")) return 0;
        return send_feedbacks(fd);
    }
    if (strcmp(cmd, "ADD_JOINT") == 0 && n == 5) {
        if (!require_role(fd, user, "ADMIN", NULL)) return 0;
        int account_id; User created;
        if (parse_positive_int(f[1], &account_id) != 0)
            return sendf_line(fd, "ERR|Invalid account number.");
        if (store_register_customer(f[2], f[3], f[4], 1, account_id,
                                    &created, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not add joint holder.");
        return sendf_line(fd, "OK|Joint holder %s added to account #%d.", f[2], account_id);
    }
    if (strcmp(cmd, "ADD_STAFF") == 0 && n == 5) {
        if (!require_role(fd, user, "ADMIN", NULL)) return 0;
        char role[BANK_ROLE_LEN]; snprintf(role, sizeof(role), "%s", f[4]);
        for (char *p = role; *p; ++p) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 'a' + 'A');
        if (store_add_staff(f[1], f[2], f[3], role, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not add staff.");
        return sendf_line(fd, "OK|%s account created for %s.", role, f[1]);
    }
    if (strcmp(cmd, "DELETE_ACCOUNT") == 0 && n == 2) {
        if (!require_role(fd, user, "ADMIN", NULL)) return 0;
        int account_id;
        if (parse_positive_int(f[1], &account_id) != 0)
            return sendf_line(fd, "ERR|Invalid account number.");
        if (store_set_account_active(account_id, 0, err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not delete account.");
        return sendf_line(fd, "OK|Account #%d deactivated (soft-deleted to preserve history).", account_id);
    }
    if (strcmp(cmd, "MODIFY_ACCOUNT") == 0 && n == 3) {
        if (!require_role(fd, user, "ADMIN", NULL)) return 0;
        int account_id;
        if (parse_positive_int(f[1], &account_id) != 0)
            return sendf_line(fd, "ERR|Invalid account number.");
        if (store_modify_account_owner_name(account_id, f[2], err, sizeof(err)) != 0)
            return sendf_line(fd, "ERR|%s", err[0] ? err : "Could not modify account owner details.");
        return sendf_line(fd, "OK|Primary account holder details updated for account #%d.", account_id);
    }
    if (strcmp(cmd, "SEARCH_ACCOUNT") == 0 && n == 2) {
        if (!require_role(fd, user, "ADMIN", NULL)) return 0;
        int account_id;
        if (parse_positive_int(f[1], &account_id) != 0)
            return sendf_line(fd, "ERR|Invalid account number.");
        Account a;
        if (store_find_account(account_id, &a) != 0)
            return sendf_line(fd, "ERR|Account not found.");
        char line[RESPONSE_CAP]; format_account_line(&a, line, sizeof(line));
        return sendf_line(fd, "OK|%s", line);
    }
    if (strcmp(cmd, "LIST_ACCOUNTS") == 0 && n == 1) {
        if (!require_role(fd, user, "ADMIN", NULL)) return 0;
        return send_accounts(fd);
    }

    return sendf_line(fd, "ERR|Unknown command or invalid arguments.");
}

static void *client_thread(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);
    (void)sendf_line(client_fd, "WELCOME|Online Banking Management System");
    User current;
    memset(&current, 0, sizeof(current));
    int logged_in = 0;
    char request[REQUEST_CAP];

    while (g_running) {
        int nread = net_recv_line(client_fd, request, sizeof(request));
        if (nread <= 0) break;
        char copy[REQUEST_CAP]; snprintf(copy, sizeof(copy), "%s", request);
        char *fields[12]; int n = split_fields(copy, fields, 12);
        if (!logged_in) {
            if (n == 1 && strcmp(fields[0], "QUIT") == 0) {
                (void)sendf_line(client_fd, "OK|Goodbye.");
                break;
            }
            if (n > 0 && strcmp(fields[0], "REGISTER") == 0) {
                if (handle_register(client_fd, fields, n) != 0) break;
                continue;
            }
            if (n > 0 && strcmp(fields[0], "LOGIN") == 0) {
                if (handle_login(client_fd, fields, n, &current, &logged_in) != 0) break;
                continue;
            }
            (void)sendf_line(client_fd, "ERR|Please LOGIN or REGISTER first.");
            continue;
        }

        int should_logout = 0;
        if (handle_command(client_fd, &current, request, &should_logout) != 0) break;
        if (should_logout) {
            session_remove(current.username);
            fprintf(stderr, "[logout] %s disconnected\n", current.username);
            logged_in = 0;
            memset(&current, 0, sizeof(current));
        }
    }
    if (logged_in) {
        session_remove(current.username);
        fprintf(stderr, "[disconnect] %s disconnected\n", current.username);
    }
    close(client_fd);
    return NULL;
}

int main(int argc, char **argv) {
    int port = 5555;
    const char *data_dir = "./data";
    if (argc >= 2) {
        char *end = NULL;
        long parsed = strtol(argv[1], &end, 10);
        if (!end || *end || parsed < 1024 || parsed > 65535) {
            fprintf(stderr, "Usage: %s [port 1024-65535] [data_dir]\n", argv[0]);
            return 2;
        }
        port = (int)parsed;
    }
    if (argc >= 3) data_dir = argv[2];
    umask(0077);
    char err[512] = {0};
    if (store_init(data_dir, err, sizeof(err)) != 0) {
        fprintf(stderr, "Database initialization failed: %s\n", err);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = stop_server;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        perror("socket");
        return 1;
    }
    int yes = 1;
    (void)setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* Localhost-only by default. */
    if (bind(g_listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("bind"); close(g_listen_fd); return 1;
    }
    if (listen(g_listen_fd, SERVER_BACKLOG) != 0) {
        perror("listen"); close(g_listen_fd); return 1;
    }

    printf("Bank server listening on 127.0.0.1:%d\n", port);
    printf("Data directory: %s\nPress Ctrl+C to stop.\n", data_dir);
    fflush(stdout);

    while (g_running) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(g_listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            if (!g_running || errno == EBADF || errno == EINVAL) break;
            perror("accept");
            continue;
        }
        int *fd_arg = malloc(sizeof(*fd_arg));
        if (!fd_arg) { close(client_fd); continue; }
        *fd_arg = client_fd;
        pthread_t tid;
        int rc = pthread_create(&tid, NULL, client_thread, fd_arg);
        if (rc != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(rc));
            close(client_fd); free(fd_arg); continue;
        }
        pthread_detach(tid);
    }
    if (g_listen_fd >= 0) close(g_listen_fd);
    fprintf(stderr, "Server stopped.\n");
    return 0;
}
