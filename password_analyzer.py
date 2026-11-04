import re
import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk

APP_TITLE = "Password Strength Analyzer"

# A small educational blocklist. It is not a complete breached-password database.
COMMON_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "qwerty123",
    "admin123", "iloveyou", "welcome123", "abc12345", "letmein123",
    "qwerty", "123456", "password1", "admin", "changeme"
}

SEQUENTIAL_PATTERNS = (
    "0123", "1234", "2345", "3456", "4567", "5678", "6789",
    "abcd", "bcde", "cdef", "qwerty", "asdf"
)


def analyze_password(password: str) -> dict:
    """Analyze a password locally and return a score, label, checks, and advice."""
    checks = {
        "At least 8 characters": len(password) >= 8,
        "At least 12 characters (recommended)": len(password) >= 12,
        "Contains lowercase letters": bool(re.search(r"[a-z]", password)),
        "Contains uppercase letters": bool(re.search(r"[A-Z]", password)),
        "Contains numbers": bool(re.search(r"\d", password)),
        "Contains special characters": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    normalized = password.lower()
    common = normalized in COMMON_PASSWORDS
    repeated = bool(re.search(r"(.)\1{3,}", password))
    sequential = any(pattern in normalized for pattern in SEQUENTIAL_PATTERNS)

    # "Uniqueness" here means not on the local common-password list and not
    # obviously predictable. It cannot prove a password is unique everywhere.
    checks["Not on built-in common-password list"] = not common
    checks["No long repeated-character run"] = not repeated
    checks["No common sequential pattern"] = not sequential

    score = sum(checks.values())
    advice = []

    if len(password) < 12:
        advice.append("Use at least 12 characters; a longer passphrase is often easier to remember.")
    if not checks["Contains uppercase letters"]:
        advice.append("Consider adding an uppercase letter.")
    if not checks["Contains lowercase letters"]:
        advice.append("Consider adding a lowercase letter.")
    if not checks["Contains numbers"]:
        advice.append("Consider adding a number.")
    if not checks["Contains special characters"]:
        advice.append("Consider adding a special character, if the service allows it.")
    if common:
        advice.append("Avoid common passwords and predictable variations.")
    if repeated:
        advice.append("Avoid long runs of the same character.")
    if sequential:
        advice.append("Avoid predictable sequences such as 1234, abcd, or qwerty.")
    if not advice:
        advice.append("No issues were detected by these basic checks. This is not a guarantee of security.")

    if not password:
        strength = "Not rated"
    elif common or len(password) < 8 or repeated or sequential or score <= 4:
        strength = "Weak"
    elif len(password) >= 12 and score >= 8:
        strength = "Strong"
    else:
        strength = "Medium"

    return {
        "strength": strength,
        "score": score,
        "max_score": len(checks),
        "checks": checks,
        "advice": advice,
        "common": common,
        "repeated": repeated,
        "sequential": sequential,
    }


def generate_password(length: int = 16) -> str:
    """Generate a password with at least one character from each main class."""
    if length < 12:
        raise ValueError("Choose a length of at least 12 characters.")

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+?"
    ]
    all_chars = "".join(groups)
    chars = [secrets.choice(group) for group in groups]
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))

    # Securely shuffle with secrets.choice rather than random.shuffle.
    shuffled = []
    while chars:
        chosen = secrets.choice(chars)
        shuffled.append(chosen)
        chars.remove(chosen)
    return "".join(shuffled)


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("700x690")
        self.root.minsize(600, 620)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10))
        style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Action.TButton", padding=8)

        outer = ttk.Frame(root, padding=22)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Password Strength Analyzer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Local password checks • No account • No network transmission",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(3, 18))

        ttk.Label(outer, text="Enter a password to analyze:", style="Section.TLabel").pack(anchor="w")
        input_row = ttk.Frame(outer)
        input_row.pack(fill="x", pady=(7, 12))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(input_row, textvariable=self.password_var, show="•")
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.password_entry.bind("<Return>", lambda _event: self.analyze())

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_row, text="Show", variable=self.show_var, command=self.toggle_visibility).pack(
            side="left", padx=(10, 0)
        )

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(0, 14))
        ttk.Button(buttons, text="Analyze Password", style="Action.TButton", command=self.analyze).pack(
            side="left"
        )
        ttk.Button(buttons, text="Clear", command=self.clear).pack(side="left", padx=8)
        ttk.Button(buttons, text="Generate Strong Alternative", command=self.suggest).pack(side="right")

        self.result_var = tk.StringVar(value="Strength: Not rated")
        ttk.Label(outer, textvariable=self.result_var, style="Section.TLabel").pack(anchor="w", pady=(0, 5))

        self.progress = ttk.Progressbar(outer, maximum=9, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 14))

        ttk.Label(outer, text="Security checks", style="Section.TLabel").pack(anchor="w")
        self.checks_frame = ttk.Frame(outer)
        self.checks_frame.pack(fill="x", pady=(6, 12))

        ttk.Label(outer, text="Recommendations", style="Section.TLabel").pack(anchor="w")
        self.advice_text = tk.Text(outer, height=5, wrap="word", state="disabled", font=("Segoe UI", 10))
        self.advice_text.pack(fill="both", expand=True, pady=(6, 10))

        ttk.Label(
            outer,
            text=("Privacy note: passwords are checked in memory only and are not saved. "
                  "The common-password list is limited; results are guidance, not a guarantee."),
            wraplength=650,
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(3, 0))

        self.password_entry.focus_set()

    def toggle_visibility(self):
        self.password_entry.configure(show="" if self.show_var.get() else "•")

    def analyze(self):
        password = self.password_var.get()
        if not password:
            messagebox.showinfo("Password required", "Enter a sample password to analyze.")
            return

        result = analyze_password(password)
        self.result_var.set(
            f"Strength: {result['strength']}     Checks passed: {result['score']}/{result['max_score']}"
        )
        self.progress.configure(value=result["score"])

        for child in self.checks_frame.winfo_children():
            child.destroy()

        for name, passed in result["checks"].items():
            symbol = "✓" if passed else "✗"
            color = "#18794e" if passed else "#b42318"
            label = tk.Label(
                self.checks_frame,
                text=f"{symbol}  {name}",
                fg=color,
                anchor="w",
                font=("Segoe UI", 10)
            )
            label.pack(fill="x", pady=1)

        self.advice_text.configure(state="normal")
        self.advice_text.delete("1.0", "end")
        for item in result["advice"]:
            self.advice_text.insert("end", "• " + item + "\n")
        self.advice_text.configure(state="disabled")

    def suggest(self):
        generated = generate_password(16)
        self.password_var.set(generated)
        self.show_var.set(True)
        self.toggle_visibility()
        self.analyze()
        messagebox.showinfo(
            "Generated alternative",
            "A new password was generated locally. Save it only in a trusted password manager."
        )

    def clear(self):
        self.password_var.set("")
        self.result_var.set("Strength: Not rated")
        self.progress.configure(value=0)
        for child in self.checks_frame.winfo_children():
            child.destroy()
        self.advice_text.configure(state="normal")
        self.advice_text.delete("1.0", "end")
        self.advice_text.configure(state="disabled")
        self.password_entry.focus_set()


def main():
    root = tk.Tk()
    PasswordAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
