#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ACCOUNTS 10

struct account {
    char name[32];
    unsigned long balance;
    void (*print_balance)(struct account*);
    void (*transfer_funds)(struct account*, unsigned long);
};

struct account* accounts[MAX_ACCOUNTS];
int account_count = 0;

void show_balance(struct account* acc) {
    printf("Account: %s\n", acc->name);
    printf("Balance: $%lu\n", acc->balance);
}

void transfer_money(struct account* acc, unsigned long amount) {
    if (acc->balance >= amount) {
        acc->balance -= amount;
        printf("Transfer of $%lu successful\n", amount);
    } else {
        printf("Insufficient funds\n");
    }
}

void admin_access() {
    printf("🏦 ADMIN ACCESS GRANTED! 🏦\n");
    printf("Accessing bank vault...\n");
    
    FILE* flag_file = fopen("./flag", "r");
    if (flag_file) {
        char flag[100];
        fgets(flag, sizeof(flag), flag_file);
        printf("FLAG: %s\n", flag);
        fclose(flag_file);
    } else {
        printf("flag{uaf_master_hacker_2024}\n");
    }
}

void create_account() {
    if (account_count >= MAX_ACCOUNTS) {
        printf("Maximum accounts reached\n");
        return;
    }
    
    struct account* new_acc = malloc(sizeof(struct account));
    if (!new_acc) {
        printf("Memory allocation failed\n");
        return;
    }
    
    printf("Enter account name: ");
    fflush(stdout);
    
    // Read input - allows both normal names and binary exploitation payloads
    ssize_t bytes_read = read(0, new_acc, sizeof(struct account));
    
    // Handle normal text input (short names)
    if (bytes_read < sizeof(struct account)) {
        // Zero out the rest of the structure
        memset((char*)new_acc + bytes_read, 0, sizeof(struct account) - bytes_read);
        
        // Remove newline if present
        if (bytes_read > 0 && new_acc->name[bytes_read-1] == '\n') {
            new_acc->name[bytes_read-1] = '\0';
        }
        
        // Set default values for normal operation
        new_acc->balance = 1000;
        new_acc->print_balance = show_balance;
        new_acc->transfer_funds = transfer_money;
    } else {
        // Handle full-size input (exploitation case)
        // Only set function pointers if they're NULL (preserves attacker control)
        if (new_acc->print_balance == NULL) {
            new_acc->print_balance = show_balance;
        }
        if (new_acc->transfer_funds == NULL) {
            new_acc->transfer_funds = transfer_money;
        }
        // Ensure name is null terminated
        new_acc->name[31] = '\0';
    }
    
    accounts[account_count] = new_acc;
    printf("Account created with ID: %d\n", account_count);
    account_count++;
}

void delete_account() {
    int idx;
    char buffer[10];
    char *endptr;
    
    printf("Enter account ID to delete: ");
    fflush(stdout);
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Use strtol with error checking instead of atoi
        idx = (int)strtol(buffer, &endptr, 10);
        
        // Check if conversion was successful
        if (endptr == buffer || (*endptr != '\n' && *endptr != '\0')) {
            printf("Invalid input - please enter a valid number\n");
            return;
        }
    } else {
        printf("Invalid input\n");
        return;
    }
    
    if (idx < 0 || idx >= account_count || !accounts[idx]) {
        printf("Invalid account ID\n");
        return;
    }
    
    printf("Deleting account: %s\n", accounts[idx]->name);
    
    // BUG: Free but don't nullify pointer (UAF vulnerability)
    free(accounts[idx]);
    
    printf("Account deleted\n");
}

void view_account() {
    int idx;
    char buffer[10];
    char *endptr;
    
    printf("Enter account ID to view: ");
    fflush(stdout);
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Use strtol with error checking instead of atoi
        idx = (int)strtol(buffer, &endptr, 10);
        
        // Check if conversion was successful
        if (endptr == buffer || (*endptr != '\n' && *endptr != '\0')) {
            printf("Invalid input - please enter a valid number\n");
            return;
        }
    } else {
        printf("Invalid input\n");
        return;
    }
    
    if (idx < 0 || idx >= account_count || !accounts[idx]) {
        printf("Invalid account ID\n");
        return;
    }
    
    // BUG: Call function pointer on potentially freed memory
    printf("\n=== Account Information ===\n");
    accounts[idx]->print_balance(accounts[idx]);
    printf("===========================\n\n");
}

void make_transfer() {
    int idx;
    unsigned long amount;
    char buffer[20];
    char *endptr;
    
    printf("Enter account ID for transfer: ");
    fflush(stdout);
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Use strtol with error checking instead of atoi
        idx = (int)strtol(buffer, &endptr, 10);
        
        // Check if conversion was successful
        if (endptr == buffer || (*endptr != '\n' && *endptr != '\0')) {
            printf("Invalid input - please enter a valid number\n");
            return;
        }
    } else {
        printf("Invalid input\n");
        return;
    }
    
    if (idx < 0 || idx >= account_count || !accounts[idx]) {
        printf("Invalid account ID\n");
        return;
    }
    
    printf("Enter transfer amount: ");
    fflush(stdout);
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Use strtoul with error checking
        amount = strtoul(buffer, &endptr, 10);
        
        // Check if conversion was successful
        if (endptr == buffer || (*endptr != '\n' && *endptr != '\0')) {
            printf("Invalid amount - please enter a valid number\n");
            return;
        }
    } else {
        printf("Invalid amount\n");
        return;
    }
    
    // BUG: Call function pointer on potentially freed memory
    accounts[idx]->transfer_funds(accounts[idx], amount);
}

void list_accounts() {
    printf("\n=== Active Accounts ===\n");
    for (int i = 0; i < account_count; i++) {
        if (accounts[i]) {
            printf("ID %d: %s (Balance: $%lu)\n", i, accounts[i]->name, accounts[i]->balance);
        }
    }
    printf("======================\n\n");
}

void print_menu() {
    printf("\n🏦 DIGITAL BANK VAULT SYSTEM 🏦\n");
    printf("1. Create Account\n");
    printf("2. Delete Account\n");
    printf("3. View Account\n"); 
    printf("4. Transfer Funds\n");
    printf("5. List Accounts\n");
    printf("6. Exit\n");
    printf("Choice: ");
    fflush(stdout);
}

int main() {
    int choice;
    char buffer[10];
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    printf("Welcome to the Digital Bank Vault!\n");
    printf("Your mission: Gain admin access to the vault system\n\n");
    
    while (1) {
        print_menu();
        
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            choice = atoi(buffer);
        } else {
            choice = 0;
        }
        
        switch (choice) {
            case 1: create_account(); break;
            case 2: delete_account(); break;
            case 3: view_account(); break;
            case 4: make_transfer(); break;
            case 5: list_accounts(); break;
            case 6: 
                printf("Exiting bank system...\n");
                exit(0);
            default:
                printf("Invalid choice\n");
        }
    }
    
    return 0;
}
