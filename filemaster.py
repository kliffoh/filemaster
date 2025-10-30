import hashlib
import os
import sys

# --- DEFENSIVE MECHANISM: SECURE PASSWORD HASHING ---

def secure_password_hasher(password: str) -> str:
    # Simulates secure hashing using SHA-256.
    SALT = "clive_security_salt_2025" 
    
    salted_password = (password + SALT).encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    
    return hashed_password

# --- DEFENSIVE MECHANISM: INPUT SANITIZATION DEMO ---

def input_sanitizer_demo(user_input: str) -> str:
    # Demonstrates defense against Injection Attacks (like XSS or SQLi) by neutralizing special characters.
    sanitized_input = user_input.replace('<', '&lt;').replace('>', '&gt;')
    sanitized_input = sanitized_input.replace('script', 'scRipt').replace('select', 'selEct')
    
    return sanitized_input

# --- DEFENSIVE UTILITY: FILE INTEGRITY AND SANITIZATION ---

def log_file_integrity_and_sanitize():
    """
    Reads a log file, verifies its integrity (via hashing), converts content to 
    uppercase for standardized analysis, and writes the sanitized output to a new file.
    Includes robust error handling for I/O operations.
    """
    print("\n[Defensive Utility: Log File Integrity & Sanitization]")
    print("OBJECTIVE: Read a source log file, verify integrity, standardize, and write to a destination file.")

    source_path = input("\n[1] Enter the SOURCE log file path to READ: ").strip()
    if source_path.lower() in ['quit', 'exit']:
        return

    destination_path = input("[2] Enter the DESTINATION file path to WRITE: ").strip()
    if destination_path.lower() in ['quit', 'exit']:
        return

    try:
        # 1. Read Original Content and Calculate Hash (Integrity Check)
        with open(source_path, 'r') as infile:
            original_content = infile.read()
        
        # Calculate the hash of the original content to check for tampering
        original_hash = hashlib.sha256(original_content.encode('utf-8')).hexdigest()
        
        print(f"\n Integrity Hash (SHA-256) of '{source_path}': {original_hash[:16]}...")
        print(f"   Successfully read {len(original_content)} characters.")

        # 2. Modification (Sanitization/Standardization)
        # Standardize log entries for easier analysis by converting to uppercase
        modified_content = original_content.upper()
        
        # 3. Writing Operation
        with open(destination_path, 'w') as outfile:
            outfile.write(modified_content)
            
        print(f" Log content standardized (UPPERCASE) and written to '{destination_path}'.")
        print("RESULT: Log data prepared for auditing or analysis.")

    except FileNotFoundError:
        print(f"\n ERROR: The source file '{source_path}' was not found.")
        print("HINT: Ensure the file exists in the current directory and check the path.")
        
    except IOError as e:
        print(f"\n I/O ERROR during file operation: Failed to read or write file.")
        print(f"HINT: Check file permissions or if another process is locking the file. Details: {e}")
            
    except Exception as e:
        print(f"\n UNEXPECTED ERROR: {e}")

# --- MAIN UTILITY LOOP ---

def Filemaster():
    user_name = "Clive Otieno here"
    
    print(f"Hello {user_name}! I'm your **Filemaster**, here to assist with cybersecurity mechanisms. ")
    print("\n--- Filemaster: Cybersecurity Utility ---")
    print("Type 'exit' or 'quit' to terminate the session.")
    
    while True:
        print("\n-------------------------------------------")
        print("Choose a mechanism to demonstrate:")
        print("1. Defensive Hashing (Password Storage)")
        print("2. Input Sanitization (Injection Countermeasure)")
        print("3. Log File Integrity & Sanitization (File I/O)")
        
        choice = input("Enter option number (1, 2, 3, or 'exit'): ").strip()
        
        if choice.lower() in ['exit', 'quit']:
            break

        if choice == '1':
            print("\n[Defensive Mechanism: Secure Password Hashing]")
            print("EXAMPLE: Demonstrates safe, non-reversible password storage using hashing.")
            
            password = input("Enter a password to hash (e.g., 'SecurePass123'): ")
            
            hashed = secure_password_hasher(password)
            
            print("\n--- Hash Result ---")
            print(f"Original Password: {password}")
            print(f"SHA-256 Hash:      {hashed}")
            print("NOTE: The same input always produces the same hash (deterministic).")
            
        elif choice == '2':
            print("\n[Defensive Mechanism: Input Sanitization]")
            print("EXAMPLE: Shows how to neutralize input that could contain malicious tags (like XSS).")
            
            malicious_input = input("Enter input, e.g., '<script>alert(\"XSS\")</script>' or 'SELECT * FROM users;': ")
            
            sanitized = input_sanitizer_demo(malicious_input)
            
            print("\n--- Sanitization Result ---")
            print(f"Original Input:   {malicious_input}")
            print(f"Sanitized Output: {sanitized}")
            print("RESULT: Malicious characters (like <, >, or SQL keywords) are safely neutralized.")
        
        elif choice == '3':
            log_file_integrity_and_sanitize()
            
        else:
            print(" Invalid choice. Please enter 1, 2, 3, or 'exit'.")

    print("\n-------------------------------------------")
    print("Pleasure serving you! Filemaster session closed. Wishing you a great day ahead. 👋")

if __name__ == "__main__":
    Filemaster()
