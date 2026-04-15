#!/bin/bash

DB_FILE="/home/user/hybrid_vas/database/hybrid_vas.db"

# Function to add a new user
add_user() {
    echo "==============================="
    echo "        Add New User"
    echo "==============================="
    read -p "Enter username: " username
    read -s -p "Enter password: " password
    echo
    read -p "Enter role (e.g., admin/user): " role

    # Hash password using SHA-256
    password_hash=$(echo -n "$password" | sha256sum | awk '{print $1}')

    sqlite3 "$DB_FILE" "INSERT INTO users (username, role, password_hash) VALUES ('$username', '$role', '$password_hash');"

    echo "✅ User '$username' added successfully!"
}

# Function to view users in a table-like structure
view_users() {
    echo "==============================="
    echo "         View Users"
    echo "==============================="
    sqlite3 -column -header "$DB_FILE" "SELECT id, username, role, password_hash FROM users;"
    echo "==============================="
    echo "End of user list."
}

# Main menu
while true; do
    clear
    echo "==============================="
    echo "      User Management Menu"
    echo "==============================="
    echo "1) Add User"
    echo "2) View Users"
    echo "3) Exit"
    echo "==============================="
    read -p "Choose an option: " choice

    case $choice in
        1) add_user ;;
        2) view_users ;;
        3) echo "Exiting User Management..."; break ;;
        *) echo "❌ Invalid option. Try again."; sleep 2 ;;
    esac
done
