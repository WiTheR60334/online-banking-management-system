#define _POSIX_C_SOURCE 200809L
#include "bank.h"
#include "net.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define INPUT_CAP 512
#define REQUEST_CAP 8192

static void trim_newline(char *s) {
    if (!s) return;
    s[strcspn(s, "\r\n")] = '\0';
}

static void sanitize_field(char *s) {
    if (!s) return;
    for (; *s; ++s) {
        if (*s == '|' || *s == '\n' || *s == '\r') *s = ' ';
    }
}

static int ask(const char *prompt, char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(out, (int)cap, stdin)) return -1;
    trim_newline(out);
    sanitize_field(out);
    return 0;
}

static int ask_password(const char *prompt, char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    printf("%s", prompt);
    fflush(stdout);
    struct termios old_term, no_echo;
    int changed = 0;
    if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
        no_echo = old_term;
        no_echo.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo) == 0) changed = 1;
    }
    if (!fgets(out, (int)cap, stdin)) {
        if (changed) (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        return -1;
    }
    if (changed) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        putchar('\n');
    }
    trim_newline(out);
    sanitize_field(out);
    return 0;
}

static int positive_int_input(const char *prompt, int *out) {
    char buf[INPUT_CAP];
    if (ask(prompt, buf, sizeof(buf)) != 0) return -1;
    char *end = NULL;
    long value = strtol(buf, &end, 10);
    if (!*buf || !end || *end || value <= 0 || value > 2147483647L) {
        puts("Enter a valid positive whole number.");
        return -1;
    }
    *out = (int)value;
    return 0;
}

static int valid_positive_money_text(const char *text) {
    if (!text || !*text) return 0;
    const unsigned char *p = (const unsigned char *)text;
    if (*p == '+') p++;
    if (!isdigit(*p)) return 0;

    int nonzero = 0;
    while (isdigit(*p)) {
        if (*p != '0') nonzero = 1;
        p++;
    }
    if (*p == '.') {
        p++;
        if (!isdigit(*p)) return 0;
        if (*p != '0') nonzero = 1;
        p++;
        if (isdigit(*p)) {
            if (*p != '0') nonzero = 1;
            p++;
            if (isdigit(*p)) return 0;
        }
    }
    return *p == '\0' && nonzero;
}

static int positive_money_input(const char *prompt, char *out, size_t cap) {
    for (;;) {
        if (ask(prompt, out, cap) != 0) return -1;
        if (valid_positive_money_text(out)) return 0;
        puts("Amount must be greater than zero. Enter a value such as 250 or 250.75.");
    }
}

/* Reads one server response and drains the full list protocol when a LIST header is received. */
static int receive_response(int fd, char *first, size_t cap, int print_response) {
    int rc = net_recv_line(fd, first, cap);
    if (rc <= 0) {
        puts("Server disconnected.");
        return -1;
    }
    if (strncmp(first, "LIST|", 5) == 0) {
        char *end = NULL;
        long count = strtol(first + 5, &end, 10);
        if (!end || (*end && *end != '|') || count < 0 || count > 100000) {
            puts("Invalid list response from server.");
            return -1;
        }
        const char *metadata = (*end == '|') ? end + 1 : NULL;
        if (print_response) {
            printf("\n--- Results (%ld) ---\n", count);
            if (metadata && *metadata) printf("%s\n", metadata);
            if (count == 0) puts("No records found.");
        }
        for (long i = 0; i < count; ++i) {
            char line[REQUEST_CAP];
            rc = net_recv_line(fd, line, sizeof(line));
            if (rc <= 0) {
                puts("Connection lost while receiving records.");
                return -1;
            }
            if (print_response) puts(line);
        }
        char ending[64];
        rc = net_recv_line(fd, ending, sizeof(ending));
        if (rc <= 0 || strcmp(ending, "END") != 0) {
            puts("Malformed list response from server.");
            return -1;
        }
        if (print_response) puts("---------------------\n");
        return 1;
    }
    if (print_response) {
        if (strncmp(first, "OK|", 3) == 0) printf("\nSUCCESS: %s\n", first + 3);
        else if (strncmp(first, "ERR|", 4) == 0) printf("\nERROR: %s\n", first + 4);
        else printf("%s\n", first);
    }
    return 1;
}

static int request(int fd, const char *line, char *response, size_t cap, int print_response) {
    if (net_send_line(fd, line) != 0) {
        puts("Could not send request to server.");
        return -1;
    }
    return receive_response(fd, response, cap, print_response);
}

static void upper(char *s) {
    for (; s && *s; ++s) *s = (char)toupper((unsigned char)*s);
}

static int login_flow(int fd, char *role, char *username, int *account_id) {
    char role_input[INPUT_CAP], pass[INPUT_CAP], response[REQUEST_CAP], request_line[REQUEST_CAP];
    puts("\nLogin role:");
    puts("  1) Customer\n  2) Joint account holder\n  3) Employee\n  4) Manager\n  5) Administrator");
    if (ask("Choose role: ", role_input, sizeof(role_input)) != 0) return -1;
    if (strcmp(role_input, "1") == 0) strcpy(role, "CUSTOMER");
    else if (strcmp(role_input, "2") == 0) strcpy(role, "JOINT");
    else if (strcmp(role_input, "3") == 0) strcpy(role, "EMPLOYEE");
    else if (strcmp(role_input, "4") == 0) strcpy(role, "MANAGER");
    else if (strcmp(role_input, "5") == 0) strcpy(role, "ADMIN");
    else { puts("Invalid role choice."); return 0; }
    if (ask("Username: ", username, BANK_USERNAME_LEN + 1) != 0 ||
        ask_password("Password: ", pass, sizeof(pass)) != 0) return -1;
    snprintf(request_line, sizeof(request_line), "LOGIN|%s|%s|%s", role, username, pass);
    if (request(fd, request_line, response, sizeof(response), 0) < 0) return -1;
    if (strncmp(response, "OK|LOGIN|", 9) != 0) {
        if (strncmp(response, "ERR|", 4) == 0) printf("\nERROR: %s\n", response + 4);
        else printf("%s\n", response);
        return 0;
    }
    char parsed[REQUEST_CAP]; snprintf(parsed, sizeof(parsed), "%s", response);
    char *f[8]; int n = 0; char *save = NULL;
    char *tok = strtok_r(parsed, "|", &save);
    while (tok && n < 8) { f[n++] = tok; tok = strtok_r(NULL, "|", &save); }
    if (n >= 5) {
        snprintf(role, BANK_ROLE_LEN, "%s", f[2]);
        snprintf(username, BANK_USERNAME_LEN + 1, "%s", f[3]);
        *account_id = atoi(f[4]);
    }
    printf("\nLogged in as %s (%s).\n", username, role);
    return 1;
}

static int submit_simple(int fd, const char *command) {
    char response[REQUEST_CAP];
    return request(fd, command, response, sizeof(response), 1);
}

static int change_password(int fd) {
    char oldp[INPUT_CAP], newp[INPUT_CAP], cmd[REQUEST_CAP];
    if (ask_password("Current password: ", oldp, sizeof(oldp)) != 0 ||
        ask_password("New password (minimum 8 characters): ", newp, sizeof(newp)) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s|%s", oldp, newp);
    return submit_simple(fd, cmd);
}

static int customer_menu(int fd, const char *role) {
    char choice[INPUT_CAP], value[INPUT_CAP], cmd[REQUEST_CAP];
    for (;;) {
        printf("\n===== %s MENU =====\n", strcmp(role, "JOINT") == 0 ? "JOINT ACCOUNT HOLDER" : "CUSTOMER");
        puts("1) Balance enquiry\n2) Deposit\n3) Withdraw\n4) Transfer funds\n5) Transaction history\n6) Change password\n7) View account details\n8) Apply for loan\n9) Add feedback\n0) Logout");
        if (ask("Choose: ", choice, sizeof(choice)) != 0) return -1;
        if (strcmp(choice, "0") == 0) { submit_simple(fd, "LOGOUT"); return 0; }
        if (strcmp(choice, "1") == 0) { if (submit_simple(fd, "BALANCE") < 0) return -1; }
        else if (strcmp(choice, "2") == 0 || strcmp(choice, "3") == 0) {
            if (positive_money_input("Amount in rupees (e.g. 250 or 250.75): ", value, sizeof(value)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "%s|%s", strcmp(choice, "2") == 0 ? "DEPOSIT" : "WITHDRAW", value);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "4") == 0) {
            int account;
            if (positive_int_input("Destination account number: ", &account) != 0) continue;
            if (positive_money_input("Amount in rupees: ", value, sizeof(value)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "TRANSFER|%d|%s", account, value);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "5") == 0) { if (submit_simple(fd, "HISTORY") < 0) return -1; }
        else if (strcmp(choice, "6") == 0) { if (change_password(fd) < 0) return -1; }
        else if (strcmp(choice, "7") == 0) { if (submit_simple(fd, "VIEW_DETAILS") < 0) return -1; }
        else if (strcmp(choice, "8") == 0) {
            if (positive_money_input("Requested loan amount in rupees: ", value, sizeof(value)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "APPLY_LOAN|%s", value);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "9") == 0) {
            if (ask("Feedback: ", value, sizeof(value)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "FEEDBACK|%s", value);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else puts("Invalid choice.");
    }
}

static int employee_menu(int fd) {
    char choice[INPUT_CAP], username[BANK_USERNAME_LEN + 1], password[INPUT_CAP];
    char fullname[BANK_NAME_LEN], cmd[REQUEST_CAP], value[INPUT_CAP];
    for (;;) {
        puts("\n===== EMPLOYEE MENU =====");
        puts("1) Add customer and account\n2) Modify customer full name\n3) View assigned loans\n4) Approve/reject assigned loan\n5) View customer transaction history\n6) Change password\n0) Logout");
        if (ask("Choose: ", choice, sizeof(choice)) != 0) return -1;
        if (strcmp(choice, "0") == 0) { submit_simple(fd, "LOGOUT"); return 0; }
        if (strcmp(choice, "1") == 0) {
            if (ask("New username: ", username, sizeof(username)) != 0 ||
                ask_password("Temporary password (min 8 chars): ", password, sizeof(password)) != 0 ||
                ask("Customer full name: ", fullname, sizeof(fullname)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "ADD_CUSTOMER|%s|%s|%s", username, password, fullname);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "2") == 0) {
            if (ask("Customer username: ", username, sizeof(username)) != 0 ||
                ask("New full name: ", fullname, sizeof(fullname)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "MODIFY_CUSTOMER|%s|%s", username, fullname);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "3") == 0) { if (submit_simple(fd, "LOANS") < 0) return -1; }
        else if (strcmp(choice, "4") == 0) {
            int loan;
            if (positive_int_input("Loan ID: ", &loan) != 0) continue;
            if (ask("Decision (APPROVE/REJECT): ", value, sizeof(value)) != 0) return -1;
            upper(value);
            snprintf(cmd, sizeof(cmd), "PROCESS_LOAN|%d|%s", loan, value);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "5") == 0) {
            int account;
            if (positive_int_input("Account number: ", &account) != 0) continue;
            snprintf(cmd, sizeof(cmd), "HISTORY_ACCOUNT|%d", account);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "6") == 0) { if (change_password(fd) < 0) return -1; }
        else puts("Invalid choice.");
    }
}

static int manager_menu(int fd) {
    char choice[INPUT_CAP], cmd[REQUEST_CAP], username[BANK_USERNAME_LEN + 1];
    for (;;) {
        puts("\n===== MANAGER MENU =====");
        puts("1) Deactivate customer account\n2) Activate customer account\n3) View all loan applications\n4) Assign loan to employee\n5) Review customer feedback\n6) Change password\n0) Logout");
        if (ask("Choose: ", choice, sizeof(choice)) != 0) return -1;
        if (strcmp(choice, "0") == 0) { submit_simple(fd, "LOGOUT"); return 0; }
        if (strcmp(choice, "1") == 0 || strcmp(choice, "2") == 0) {
            int account;
            if (positive_int_input("Account number: ", &account) != 0) continue;
            snprintf(cmd, sizeof(cmd), "SET_ACCOUNT_STATUS|%d|%s", account,
                     strcmp(choice, "1") == 0 ? "INACTIVE" : "ACTIVE");
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "3") == 0) { if (submit_simple(fd, "LOANS") < 0) return -1; }
        else if (strcmp(choice, "4") == 0) {
            int loan;
            if (positive_int_input("Loan ID to assign: ", &loan) != 0) continue;
            if (ask("Employee username: ", username, sizeof(username)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "ASSIGN_LOAN|%d|%s", loan, username);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "5") == 0) { if (submit_simple(fd, "FEEDBACKS") < 0) return -1; }
        else if (strcmp(choice, "6") == 0) { if (change_password(fd) < 0) return -1; }
        else puts("Invalid choice.");
    }
}

static int admin_menu(int fd) {
    char choice[INPUT_CAP], cmd[REQUEST_CAP], username[BANK_USERNAME_LEN + 1];
    char password[INPUT_CAP], fullname[BANK_NAME_LEN], role[INPUT_CAP];
    for (;;) {
        puts("\n===== ADMINISTRATOR MENU =====");
        puts("1) Add customer account\n2) Delete (deactivate) account\n3) Modify primary holder full name\n4) Search account\n5) List all accounts\n6) Add joint account holder\n7) Create employee/manager login\n8) Activate/deactivate account\n9) List loans\n10) Review feedback\n11) Change password\n0) Logout");
        if (ask("Choose: ", choice, sizeof(choice)) != 0) return -1;
        if (strcmp(choice, "0") == 0) { submit_simple(fd, "LOGOUT"); return 0; }
        if (strcmp(choice, "1") == 0) {
            if (ask("New username: ", username, sizeof(username)) != 0 ||
                ask_password("Temporary password (min 8 chars): ", password, sizeof(password)) != 0 ||
                ask("Customer full name: ", fullname, sizeof(fullname)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "ADD_CUSTOMER|%s|%s|%s", username, password, fullname);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "2") == 0) {
            int account;
            if (positive_int_input("Account number to delete: ", &account) != 0) continue;
            snprintf(cmd, sizeof(cmd), "DELETE_ACCOUNT|%d", account);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "3") == 0) {
            int account;
            if (positive_int_input("Account number: ", &account) != 0) continue;
            if (ask("New primary holder full name: ", fullname, sizeof(fullname)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "MODIFY_ACCOUNT|%d|%s", account, fullname);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "4") == 0) {
            int account;
            if (positive_int_input("Account number: ", &account) != 0) continue;
            snprintf(cmd, sizeof(cmd), "SEARCH_ACCOUNT|%d", account);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "5") == 0) { if (submit_simple(fd, "LIST_ACCOUNTS") < 0) return -1; }
        else if (strcmp(choice, "6") == 0) {
            int account;
            if (positive_int_input("Existing account number: ", &account) != 0) continue;
            if (ask("Joint holder username: ", username, sizeof(username)) != 0 ||
                ask_password("Joint holder password (min 8 chars): ", password, sizeof(password)) != 0 ||
                ask("Joint holder full name: ", fullname, sizeof(fullname)) != 0) return -1;
            snprintf(cmd, sizeof(cmd), "ADD_JOINT|%d|%s|%s|%s", account, username, password, fullname);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "7") == 0) {
            if (ask("New staff username: ", username, sizeof(username)) != 0 ||
                ask_password("Password (min 8 chars): ", password, sizeof(password)) != 0 ||
                ask("Full name: ", fullname, sizeof(fullname)) != 0 ||
                ask("Role (EMPLOYEE/MANAGER): ", role, sizeof(role)) != 0) return -1;
            upper(role);
            snprintf(cmd, sizeof(cmd), "ADD_STAFF|%s|%s|%s|%s", username, password, fullname, role);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "8") == 0) {
            int account;
            if (positive_int_input("Account number: ", &account) != 0) continue;
            if (ask("Status (ACTIVE/INACTIVE): ", role, sizeof(role)) != 0) return -1;
            upper(role);
            snprintf(cmd, sizeof(cmd), "SET_ACCOUNT_STATUS|%d|%s", account, role);
            if (submit_simple(fd, cmd) < 0) return -1;
        } else if (strcmp(choice, "9") == 0) { if (submit_simple(fd, "LOANS") < 0) return -1; }
        else if (strcmp(choice, "10") == 0) { if (submit_simple(fd, "FEEDBACKS") < 0) return -1; }
        else if (strcmp(choice, "11") == 0) { if (change_password(fd) < 0) return -1; }
        else puts("Invalid choice.");
    }
}

static int register_flow(int fd) {
    char username[BANK_USERNAME_LEN + 1], password[INPUT_CAP];
    char fullname[BANK_NAME_LEN], cmd[REQUEST_CAP], response[REQUEST_CAP];
    puts("\nCreate a new single-owner customer account");
    if (ask("Username (letters, digits, dot, underscore, hyphen): ", username, sizeof(username)) != 0 ||
        ask_password("Password (minimum 8 characters): ", password, sizeof(password)) != 0 ||
        ask("Full name: ", fullname, sizeof(fullname)) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "REGISTER|%s|%s|%s|SINGLE", username, password, fullname);
    if (request(fd, cmd, response, sizeof(response), 1) < 0) return -1;
    puts("Joint holders can be added by an administrator after the account is created.");
    return 0;
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 5555;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) {
        char *end = NULL;
        long p = strtol(argv[2], &end, 10);
        if (!end || *end || p < 1 || p > 65535) {
            fprintf(stderr, "Usage: %s [host] [port]\n", argv[0]);
            return 2;
        }
        port = (int)p;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) {
        fprintf(stderr, "Host must be an IPv4 address, e.g. 127.0.0.1.\n");
        close(fd); return 2;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(stderr, "Could not connect to %s:%d: %s\n", host, port, strerror(errno));
        close(fd); return 1;
    }
    char response[REQUEST_CAP];
    if (receive_response(fd, response, sizeof(response), 1) < 0) { close(fd); return 1; }

    int done = 0;
    while (!done) {
        char choice[INPUT_CAP], role[BANK_ROLE_LEN] = {0};
        char username[BANK_USERNAME_LEN + 1] = {0};
        int account_id = 0;
        puts("\n===== ONLINE BANKING =====");
        puts("1) Login\n2) Create customer account\n0) Exit");
        if (ask("Choose: ", choice, sizeof(choice)) != 0) break;
        if (strcmp(choice, "0") == 0) {
            (void)request(fd, "QUIT", response, sizeof(response), 1);
            done = 1;
        } else if (strcmp(choice, "2") == 0) {
            if (register_flow(fd) < 0) done = 1;
        } else if (strcmp(choice, "1") == 0) {
            int login = login_flow(fd, role, username, &account_id);
            if (login < 0) { done = 1; continue; }
            if (login == 0) continue;
            int rc;
            if (strcmp(role, "CUSTOMER") == 0 || strcmp(role, "JOINT") == 0) rc = customer_menu(fd, role);
            else if (strcmp(role, "EMPLOYEE") == 0) rc = employee_menu(fd);
            else if (strcmp(role, "MANAGER") == 0) rc = manager_menu(fd);
            else if (strcmp(role, "ADMIN") == 0) rc = admin_menu(fd);
            else rc = -1;
            if (rc < 0) done = 1;
        } else puts("Invalid choice.");
    }
    close(fd);
    return 0;
}
