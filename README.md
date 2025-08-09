# Folder_Encryption_Using_AES
## Overview
The Folder Encryption project is designed to protect sensitive data by encrypting the contents of folders using the AES (Advanced Encryption Standard) algorithm. It transforms files into an unreadable format to prevent unauthorized access and maintain confidentiality and integrity of data.

## Features
- **AES Encryption & Decryption:** Uses AES-256 for strong, reliable encryption.
- **User Authentication:** Secure login system to ensure only authorized users access encrypted folders.
- **Automatic Password Generation:** Creates strong, random passwords for encrypting folders.
- **Email Notifications:** Sends passwords or alerts via email to the registered user.
- **User-Friendly Interface:** Simple and intuitive interface to easily encrypt/decrypt folders.
- **Logging and Auditing:** Keeps track of user activities for security monitoring.

---

## Technologies Used
- **Programming Language:** Python 
- **Encryption Library:** PyCryptodome 
- **Database:** SQLite
- **Email Service:** SMTP
- **Frontend:** Tkinter


## How It Works
1. **User Registration/Login:** Users register and authenticate with the system.
2. **Random Password generation:**Users can generate any random password and the password will be saved in local memory.
3. **Folder Selection:** Users select the folder they want to encrypt or decrypt.
4. **Encryption:** The system uses AES-256 to encrypt files within the folder.
5. **Password Generation:** A strong random password is generated for encryption.
6. **Email Notification:** The password is sent to the user’s registered email.
7. **Decryption:** Using the password, users can decrypt the folder to access original files.


### Prerequisites
- Python 
- Required libraries 


**Usage**:
Encrypt Folder: Select folder, encrypt with generated password, receive password by email.
Decrypt Folder: Enter password to decrypt and access files.
User Management: Register and login to access the system securely.



<img width="568" height="491" alt="image" src="https://github.com/user-attachments/assets/b9a77039-47d9-4a2f-a3e6-307c3ba3653c" />
                    
                     **Login page for user authentication.**


<img width="568" height="491" alt="image" src="https://github.com/user-attachments/assets/b26a83e1-e38e-4636-a694-167d688bd462" />
                
                 **Interface to select and encrypt folders.**


<img width="568" height="491" alt="image" src="https://github.com/user-attachments/assets/8191e62c-e714-49bf-8897-8820674836f9" />
               
                 **Enter the folder to be encryptrd and email along with smtp password**


<img width="779" height="669" alt="image" src="https://github.com/user-attachments/assets/e61505f3-79ce-4778-8987-e7d4c083ad0b" />

                  **Sample email showing the generated password.**



**Security Considerations:**

AES-256 encryption ensures strong protection.

Passwords are randomly generated and securely emailed.

User authentication prevents unauthorized access.

Future scope to add multi-factor authentication.

