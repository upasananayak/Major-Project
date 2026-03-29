import sys
from blockchain import Blockchain

def show_history(filename):
    bc = Blockchain()
    print(f"\n--- History for '{filename}' ---")
    
    versions = bc.get_file_history(filename)
    
    if not versions:
        print("No history found.")
        return

    print(f"{'#':<4} | {'Version ID':<30} | {'Status'}")
    print("-" * 50)
    
    for i, ver_id in enumerate(versions):
        is_deleted = bc.is_file_deleted(ver_id)
        
        if is_deleted:
            status = "DELETED"
        else:
            status = "Active"
            
        print(f"{i+1:<4} | {ver_id:<30} | {status}")

    print("-" * 50)
    print(f"Total Modifications: {len(versions)}")

def delete_file(filename):
    bc = Blockchain()
    print(f"\n--- Deleting '{filename}' ---")
    
    confirm = input(f"Are you sure you want to delete '{filename}'? (yes/no): ")
    if confirm.lower() == "yes":
        success = bc.delete_file(filename)
        if success:
            print("Success! The file is logically deleted from the Master Directory.")
            print("Users trying to verify it will now fail.")
    else:
        print("Deletion cancelled.")

def main():
    while True:
        print("\n=== File Management System ===")
        print("1. View File History")
        print("2. Delete a File")
        print("3. Exit")
        
        choice = input("Select an option: ")
        
        if choice == '1':
            fname = input("Enter filename (e.g., input.txt): ").strip()
            show_history(fname)
        elif choice == '2':
            fname = input("Enter filename (e.g., input.txt): ").strip()
            delete_file(fname)
        elif choice == '3':
            sys.exit()
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()