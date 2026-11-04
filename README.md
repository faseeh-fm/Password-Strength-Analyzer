# Password Strength Analyzer

A Python desktop application for an introductory cybersecurity project. It checks password length, character variety, a small common-password list, repeated characters, and common sequences. It gives feedback and can generate a stronger alternative.

## Features

- Tkinter graphical interface
- Password length and complexity checks
- Basic common-password and predictable-pattern checks
- Weak, Medium, and Strong labels
- Actionable feedback
- Password generation using Python's `secrets` module
- Automated unit tests using `unittest`
- No third-party packages required

## Requirements

- Python 3.10+ recommended
- Tkinter (included with most standard Windows Python installations)
- No external Python packages

## Run the application

1. Download or clone this repository.
2. Open a terminal in the project folder.
3. Run:

   ```bash
   python password_analyzer.py
   ```

   On some Windows systems, use `py password_analyzer.py`.

## Run the tests

```bash
python -m unittest -v
```

## How it works

The analyzer applies simple local rules to a password and returns checks, a heuristic strength label, and suggestions. The generator uses Python's `secrets` module for random choices.

## Security and privacy notes

- The application does not save or transmit entered passwords.
- Use fictional test passwords when demonstrating the project.
- The common-password list is small and educational, not a complete breach list.
- The score and labels are heuristic guidance, not a guarantee that a password is safe.
- This project does not check whether a password has appeared in real-world breaches.
- Generated passwords should be stored in a reputable password manager, not in source code or screenshots.

## Limitations and future work

- Expand common-password detection with a safely sourced blocklist.
- Add more robust password-strength estimation.
- Optionally add password reuse prevention using carefully designed local storage; never store plaintext passwords.

## Project structure

```text
Password-Strength-Analyzer/
├── password_analyzer.py
├── test_analyzer.py
├── README.md
├── requirements.txt
├── .gitignore
└── screenshots/
```

## Author

Add your name and student/program details here if appropriate for your submission.
