#importing re library of python,which can be used to work with Regular Expressions
import re

#Checking strength of the password
def password_strength(password):
    # Check the length of the password
    if len(password) > 8:
        return "Strong"
    elif 6 < len(password) <= 8:
        return "Medium"
    elif len(password) <= 5:
        return "Weak"

def is_password_strong(password):
    # Check for the presence of uppercase letters, lowercase letters, digits, and special characters
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]', password))
    
    if has_uppercase and has_lowercase and has_digit and has_special:
        return True
    else:
        return False

#defining the main function here
def main():
    password = input("Enter your password: ")
    
    if is_password_strong(password):
        print("Password is strong.")
    else:
        strength = password_strength(password)
        print(f"Password is {strength}.")

if __name__ == "__main__":
    main()
