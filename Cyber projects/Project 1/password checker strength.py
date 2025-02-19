import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import requests

def is_common_password(password, filepath='common_passwords.txt'):
    """
    Check if the password is present in the common_passwords.txt file.
    """
    try:
        with open(filepath, 'r') as f:
            common_passwords = f.read().splitlines()
        # Check case-insensitively
        return password.lower() in (p.lower() for p in common_passwords)
    except FileNotFoundError:
        # If file doesn't exist, skip the check.
        return False

def advanced_password_strength(password):
    """
    Evaluate the password's strength using multiple criteria and return a score with a strength label.
    """
    score = 0

    # Length criteria: 8+ gets 2 points; 12+ gets an extra 2.
    if len(password) >= 8:
        score += 2
    if len(password) >= 12:
        score += 2

    # Character variety criteria.
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1

    # Deduct points for common sequences or patterns.
    sequences = [
        "0123", "1234", "2345", "3456", "4567", "5678", "6789",
        "abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij"
    ]
    for seq in sequences:
        if seq in password.lower():
            score -= 1

    # Classify password strength.
    if score >= 8:
        return f"Score: {score} - Very Strong 💪"
    elif score >= 5:
        return f"Score: {score} - Strong 😊"
    elif score >= 3:
        return f"Score: {score} - Moderate 😐"
    else:
        return f"Score: {score} - Weak ❌"

def check_pwned(password):
    """
    Check the password against the Have I Been Pwned API.
    Returns the number of times the password has appeared in data breaches.
    """
    # Hash the password using SHA-1.
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]
    
    # Query the API with the prefix.
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError("Error fetching data from the API.")

    # Compare the suffix with returned hash suffixes.
    hashes = (line.split(':') for line in res.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0

def check_strength():
    """
    Gather the password input from the GUI, perform checks, and display results.
    """
    pwd = entry.get()
    if not pwd:
        messagebox.showwarning("Input Error", "Please enter a password!")
        return

    result_msg = ""
    
    # Check if the password is common.
    if is_common_password(pwd):
        result_msg += "This password is common. Please choose a different one.\n"
    
    # Get the advanced password strength.
    strength = advanced_password_strength(pwd)
    result_msg += "Password Strength: " + strength + "\n\n"

    # Check for password breaches using the Have I Been Pwned API.
    try:
        breaches = check_pwned(pwd)
        if breaches > 0:
            result_msg += f"Warning: This password has been seen {breaches} times in data breaches."
        else:
            result_msg += "Good news: This password was not found in any data breaches!"
    except Exception as e:
        result_msg += f"Error checking data breaches: {e}"

    messagebox.showinfo("Password Analysis", result_msg)

# --- GUI Setup ---
root = tk.Tk()
root.title("Advanced Password Strength Checker")

tk.Label(root, text="Enter Password:").pack(pady=5)
entry = tk.Entry(root, width=40, show="*")
entry.pack(pady=5)

tk.Button(root, text="Check Strength", command=check_strength).pack(pady=20)

root.mainloop()
