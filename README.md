# Secure Password Generator
The Secure Password Generator is a Python desktop GUI tool built with Tkinter. It generates secure passwords and memorable passphrases using Python’s secrets module, which provides cryptographically secure randomness. It focuses on usability and security awareness by combining generation, validation, and safe handling of sensitive data. 

<img width="721" height="953" alt="Screenshot 2026-05-13 at 13 08 15" src="https://github.com/user-attachments/assets/76c66486-df7d-4532-8ed5-655f33ec1c0e" />

## Features
* Secure password generation using Python’s `secrets` module
* Password length control
* Number of passwords to generate
* Uppercase, lowercase, number, and symbol options
* Ambiguous character removal
* Passphrase mode
* Password strength estimation
* Color-coded strength labels
* Check your own password strength
* Click-to-copy single password
* Copy selected passwords
* Copy all passwords
* Select all and uncheck all controls
* Clear results and clipboard
* Clipboard auto-clear with countdown
* CSV export for password manager import
* Responsive Tkinter UI
* Button hover and press feedback

How To

## Important:
* The app cannot remove content that has already been pasted into another app.
* Clipboard managers may also retain copied content.
* CSV Export Warning
  * CSV exports are plain text.
  * After importing the CSV into a password manager, delete the CSV file.
* Generated passwords are not stored automatically. They exist only in:
  * The application UI
  * Temporary memory
  * The system clipboard (temporarily)
  * CSV export if explicitly chosen by the user

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

### Security Notes
* This project is intended for learning, personal security practice, and portfolio demonstration.
* For real credential storage, use a trusted password manager.


