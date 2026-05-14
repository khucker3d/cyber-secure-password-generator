# Secure Password Generator

A Python desktop GUI tool for generating secure passwords and readable passphrases using cryptographically secure randomness.

## Features
- Secure password generation using Python’s `secrets` module
- Password length control
- Number of passwords to generate
- Uppercase, lowercase, number, and symbol options
- Ambiguous character removal
- Passphrase mode
- Password strength estimation
- Color-coded strength labels
- Check your own password strength
- Click-to-copy single password
- Copy selected passwords
- Copy all passwords
- Select all and uncheck all controls
- Clear results and clipboard
- Clipboard auto-clear with countdown
- CSV export for password manager import
- Responsive Tkinter UI
- Button hover and press feedback

## Screenshot
<img width="521" height="753" alt="Screenshot 2026-05-13 at 13 08 15" src="https://github.com/user-attachments/assets/abeb6182-4df5-44fe-9bd7-a870e34069f2" />

## Tech Stack
* Python
* Tkinter
* secrets
* csv
* math
* string
* time

## Installation
1. Download the secure_password_generator.py script
2. Run the script
   * Mac Terminal: python3 secure_password_generator.py
   * Windows PowerShell: python secure_password_generator.py
   *Note: I used IDLE to create and run the script*
3. Set password length
4. Set number to generate
5. Enable character options
6. Enable passphrase mode if desired
7. Click Generate
Results: Generated results appear with strength labels.

### You can:
* Click one result to copy it
* Select multiple results and click Copy Selected
* Click Copy All
* Clear results
* Clear clipboard manually
* Export generated results to CSV

### Passphrase Mode:
Passphrase mode generates readable passwords such as:
* forest-rocket-cloud-signal-A7!
* Enabled character options are appended to the passphrase to support websites that require uppercase letters, lowercase letters, numbers, or symbols.
* Clipboard Safety
* Copied passwords start a countdown timer.
  * After 30 seconds:
    * The clipboard is overwritten
    * The clipboard is cleared

## Important:
* The app cannot remove content that has already been pasted into another app. Clipboard managers may also retain copied content.
* CSV Export Warning
  * CSV exports are plain text.
  * After importing the CSV into a password manager, delete the CSV file.

### Limitations
* Strength estimation is entropy-based
* No breach database checking
* No password reuse detection
* CSV exports are not encrypted
* Clipboard managers may retain copied values
* Python cannot guarantee low-level secure memory wiping

### Security Notes
* This project is intended for learning, personal security practice, and portfolio demonstration.
* For real credential storage, use a trusted password manager.

## Future Improvement Ideas: 
* Larger Diceware-style word list
* Dark mode polish
* Password visibility toggle for custom checker
* Optional breach-check integration
* Encrypted export option
* Packaged Mac and Windows app builds

## License
MIT License


