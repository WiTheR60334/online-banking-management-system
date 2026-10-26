# EG 301 Operating Systems Mini Project Report

## Title
Design and Development of an Online Banking Management System in C

## Objective
To implement a client-server banking system demonstrating operating-system facilities: sockets and IPC, concurrent client handling, system-call-based file operations, record locking, critical sections, and role-based access control.

## Problem statement
The server maintains users, accounts, transactions, loan requests, and feedback in flat files. Customers and joint holders can view their account information and transact after authentication. Employees process assigned loans and maintain customer details. Managers control account availability, assign loan applications, and review feedback. Administrators manage accounts and staff access.

## Architecture and modules

| Module | Responsibility |
|---|---|
| `client.c` | Interactive terminal interface, password input without terminal echo, socket connection and request creation |
| `server.c` | Listening socket, client worker threads, login/session management, role validation, request dispatch |
| `store.c` | Flat-file persistence, fixed-size record parsing, `fcntl` locking, password hashing, transaction/loan operations |
| `net.c` | Newline-delimited TCP message transport |

The data store consists of `users.db`, `accounts.db`, `transactions.db`, `loans.db`, `feedback.db`, and the append-only `journal.db` write-ahead log. The ZIP includes `architecture.png` / `architecture.svg` for the deployment architecture and `blueprint.png` / `blueprint.svg` for the C modules and record structures, with their editable Graphviz sources. See `README.md` for record schemas, recovery flow, and test instructions.

## Operating Systems concepts

1. **IPC and sockets:** the client and server communicate with TCP sockets on the loopback interface.
2. **Multithreading:** each accepted client gets a detached pthread worker, so separate sessions can progress concurrently.
3. **File management:** the server uses file descriptors and system calls such as `open`, `pread`, `pwrite`, `fstat`, `fdatasync`, and `close`.
4. **File locking:** fixed-size records allow byte-range `fcntl` read and write locks. Read operations use `F_RDLCK`; transactions and account metadata changes use `F_WRLCK`.
5. **Synchronization:** per-file pthread mutexes protect same-process threads because classic POSIX `fcntl` locks are associated with the process rather than with individual threads.
6. **Critical sections:** the source and destination records are locked in stable order during transfers; funds and account status are validated before balances change.
7. **Write-ahead logging and recovery:** financial changes first append and sync a `PREPARED` journal entry. Startup recovery replays incomplete entries using intended post-balances, journal IDs for exactly-once transaction rows, and idempotent loan-state updates. A `COMMITTED` marker is appended after all related records are synced.
8. **Persistence error handling:** writes, `fdatasync`, and directory initialization `fsync` results are checked. If a financial update fails after a durable journal prepare, the server stops rather than serving partial state; startup recovery must succeed before it accepts clients.
9. **Authentication and authorization:** salted PBKDF2 password hashes, role checks, and a single-session registry are used.

## Important validations

- A withdrawal or transfer is rejected if the source balance is insufficient.
- A transfer is rejected if the destination account does not exist, is inactive, or is the same as the source.
- Inactive accounts cannot log in or perform banking actions.
- Joint account holders share a single account balance.
- Approved loans are credited and written to transaction history as one recoverable journaled operation; replay cannot credit the same loan twice.
- A transaction-history row stores its originating journal ID so that recovery can detect already-appended entries.
- Account deletion is a soft deletion so that historical records remain consistent.
- Monetary values are stored as integer paise.
- Zero/invalid transfer amounts receive a specific validation message rather than a misleading protocol-format error.
- Repeating an activation/deactivation operation reports that the account is already in the requested state.
- Loan listings show `UNASSIGNED` before assignment and the assigned employee username afterward.
- Transaction history shows the current account balance and a per-entry running balance, reconstructed from ledger entries.

## Automated concurrency and recovery validation

Run `make test`. The test target verifies 200 simultaneous transfers in four pthreads and 50 transfers from two separate processes. It injects process exits immediately after `PREPARED`, after the first transfer-account write, after both transfer-account writes, after the loan-approval transaction row but before the loan status update, and after loan status is updated but before the `COMMITTED` marker. Recovery checks account balances, the final loan status, exactly one transaction-history row, idempotence across repeated startup, rejection of a duplicate approval, and repair of a torn trailing journal row.

## Test checklist

- [ ] Create a customer and log in with the customer role.
- [ ] Reject a login with an incorrect password or wrong role.
- [ ] Reject a second simultaneous session for the same username.
- [ ] Deposit and verify the updated balance and transaction record.
- [ ] Reject an overdrawn withdrawal.
- [ ] Transfer funds to another valid account and verify both balances.
- [ ] Reject a transfer to an unknown or inactive account.
- [ ] Add a joint holder and verify shared balance and history.
- [ ] Change a password and confirm that the old password no longer works.
- [ ] Assign a loan as manager, approve/reject it as the assigned employee, and verify approval credit.
- [ ] Submit feedback and read it as manager/admin.
- [ ] Deactivate an account and verify that banking actions are blocked.
- [ ] Connect several clients and exercise operations concurrently.

## Limitations
The journal provides redo-based process-crash recovery for deposits, withdrawals, transfers, and loan approvals, assuming the underlying filesystem honors successful `fdatasync`/`fsync` calls. A durable `PREPARED` record is treated as the transaction's decision to commit, so recovery may complete it even if the client did not receive a reply; clients should query account history before retrying after a disconnect. Administrative metadata edits and loan assignment/rejection are not multi-record journal transactions. The application uses no TLS and assumes only one server instance uses a data directory because active-session state is kept in memory. It is not production banking software.

## Build and run

```bash
sudo pacman -S --needed base-devel openssl
make
make test
./server 5555 ./data
# In another terminal:
./client 127.0.0.1 5555
```

The first server startup prints initial demo credentials for `admin`, `manager`, and `employee`. Change them after first login.
