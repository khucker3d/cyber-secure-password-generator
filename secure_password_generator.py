# secure_password_generator_gui_safe.py

import csv
import math
import secrets # secrets is used instead of random because password generation needs & cryptographically secure randomness.
import string
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog


# =========================================================
# Constants
# =========================================================

AMBIGUOUS = "O0Il1" # Characters that are easy to confuse visually. Removing these improves readability when users need to type passwords manually.
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# This is a small local word list for passphrase mode.
# For stronger production passphrases, this could be replaced with a larger
# Diceware-style word list.
PASSPHRASE_WORDS = [
    "anchor", "apple", "artist", "autumn", "binary", "bridge", "candle", "castle",
    "cedar", "cloud", "coffee", "comet", "copper", "crystal", "delta", "dragon",
    "ember", "falcon", "forest", "galaxy", "garden", "harbor", "island", "jacket",
    "kernel", "lantern", "matrix", "meadow", "mirror", "nebula", "ocean", "orange",
    "packet", "planet", "pixel", "quantum", "radar", "river", "rocket", "saffron",
    "shadow", "signal", "silver", "socket", "stone", "summit", "thunder", "tiger",
    "token", "valley", "vector", "violet", "window", "winter", "zephyr"
]


# =========================================================
# Utility Functions
# =========================================================

def remove_ambiguous(chars):
    """Remove confusing characters like O, 0, I, l, and 1."""
    return "".join(char for char in chars if char not in AMBIGUOUS)


def estimate_strength(secret_text, pool_size):
    """
    Estimate password strength using entropy.

    Entropy is calculated as:
        password length * log2(character pool size)

    This is a useful estimate, but not a full password audit.
    It does not check for dictionary words, reused passwords, or leaked passwords.
    """
    entropy = len(secret_text) * math.log2(pool_size)

    if entropy < 50:
        return "Weak", entropy
    elif entropy < 80:
        return "Moderate", entropy
    elif entropy < 110:
        return "Strong", entropy
    else:
        return "Very Strong", entropy


def strength_color(strength):
    """Return color for strength label."""
    if strength == "Weak":
        return "#FF0000"
    if strength == "Moderate":
        return "#FF9900"
    if strength == "Strong":
        return "#00D945"
    return "#00FF51"


def generate_password(length, use_upper, use_lower, use_numbers, use_symbols, avoid_ambiguous):
    """
    Generate a secure random password.

    Important security behavior:
    - Uses secrets.choice() for secure randomness.
    - Requires at least one selected character group.
    - Ensures at least one character from each selected group.
    - Shuffles the final password so required characters are not predictable.
    """
    groups = []

    if use_upper:
        groups.append(string.ascii_uppercase)

    if use_lower:
        groups.append(string.ascii_lowercase)

    if use_numbers:
        groups.append(string.digits)

    if use_symbols:
        groups.append(SYMBOLS)

    if not groups:
        raise ValueError("Select at least one character type.")

    if avoid_ambiguous:
        groups = [remove_ambiguous(group) for group in groups]

    if length < len(groups):
        raise ValueError("Password length is too short for selected options.")

    all_chars = "".join(groups)
    password_chars = []

    # Guarantee at least one character from each selected group.
    # Without this, a random password could technically miss numbers, symbols,
    # or uppercase letters even when those options are enabled.
    for group in groups:
        password_chars.append(secrets.choice(group))

    # Fill remaining characters.
    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    # Shuffle the password after adding required characters.
    # This prevents the first characters from always following the same pattern.
    secrets.SystemRandom().shuffle(password_chars)

    password = "".join(password_chars)
    strength, entropy = estimate_strength(password, len(all_chars))

    return password, strength, entropy


def generate_passphrase(word_count, add_upper, add_lower, add_number, add_symbol, avoid_ambiguous):
    """
        Generate a memorable passphrase.

        The passphrase uses random words, then optionally appends extra characters
        based on the selected password options.

        Example:
            river-cloud-anchor-signal-A7!
        """
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]

    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    number_chars = string.digits
    symbol_chars = SYMBOLS

    if avoid_ambiguous:
        upper_chars = remove_ambiguous(upper_chars)
        lower_chars = remove_ambiguous(lower_chars)
        number_chars = remove_ambiguous(number_chars)

    extra_chars = []

    if add_upper:
        extra_chars.append(secrets.choice(upper_chars))

    if add_lower:
        extra_chars.append(secrets.choice(lower_chars))

    if add_number:
        extra_chars.append(secrets.choice(number_chars))

    if add_symbol:
        extra_chars.append(secrets.choice(symbol_chars))

    if extra_chars:
        secrets.SystemRandom().shuffle(extra_chars)
        passphrase = "-".join(words) + "-" + "".join(extra_chars)
    else:
        passphrase = "-".join(words)

    entropy = word_count * math.log2(len(PASSPHRASE_WORDS))

    if add_upper:
        entropy += math.log2(len(upper_chars))

    if add_lower:
        entropy += math.log2(len(lower_chars))

    if add_number:
        entropy += math.log2(len(number_chars))

    if add_symbol:
        entropy += math.log2(len(symbol_chars))

    if entropy < 50:
        strength = "Moderate"
    elif entropy < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return passphrase, strength, entropy


# =========================================================
# GUI Application
# =========================================================

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Generator")
        self.root.geometry("710x920")
        self.root.minsize(720, 720)     # minimum size
        self.root.resizable(True, True) # allow width + height resize

        # User settings.
        self.length_var = tk.IntVar(value=20)
        self.count_var = tk.IntVar(value=5)
        self.words_var = tk.IntVar(value=5)

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.ambiguous_var = tk.BooleanVar(value=True)
        self.passphrase_mode_var = tk.BooleanVar(value=False)

        # Custom password checker.
        self.custom_password_var = tk.StringVar()

        # Generated output storage.
        self.generated_items = []
        self.check_vars = []

        # Clipboard countdown.
        self.clipboard_clear_after_ms = 30000
        self.clipboard_timer_id = None
        self.clipboard_seconds_remaining = 0

        self.build_ui()

    def make_button(self, parent, text, command, row, column):
        """
        Creates a clean gray button with hover + press states.
        """

        NORMAL_BG = "#D1D5DB"   # light gray
        HOVER_BG  = "#9CA3AF"   # medium gray
        PRESS_BG  = "#6B7280"   # dark gray
        TEXT_COLOR = "#000000"  # black

        button = tk.Button(
            parent,
            text=text,
            command=command,
            width=12,
            bg=NORMAL_BG,
            fg=TEXT_COLOR,
            activebackground=PRESS_BG,
            activeforeground=TEXT_COLOR,
            relief="flat",
            borderwidth=0,
            cursor="hand2"
        )

        button.grid(row=row, column=column, padx=5, pady=5)

        # Hover effect
        button.bind("<Enter>", lambda e: button.config(bg=HOVER_BG))
        button.bind("<Leave>", lambda e: button.config(bg=NORMAL_BG))

        # Press effect (mouse down)
        button.bind("<ButtonPress-1>", lambda e: button.config(bg=PRESS_BG))

        # Release → back to hover color (if still hovered)
        button.bind("<ButtonRelease-1>", lambda e: button.config(bg=HOVER_BG))

        return button

    # =====================================================
    # UI Layout
    # =====================================================

    def build_ui(self):
        """Build full scrollable UI."""

        # The main app is placed inside a scrollable canvas so the UI can still be used
        # if the window is smaller than the full content height.
        main_canvas = tk.Canvas(
            self.root,
            highlightthickness=0
        )

        main_scrollbar = tk.Scrollbar(
            self.root,
            orient="vertical",
            command=main_canvas.yview
        )

        self.main_frame = tk.Frame(main_canvas, width=690, bg="#2B2B2B")

        self.main_frame.bind(
            "<Configure>",
            lambda event: main_canvas.configure(
                scrollregion=main_canvas.bbox("all")
            )
        )

        # Fixed-width centered content.
        self.canvas_window = main_canvas.create_window(
            (0, 0),
            window=self.main_frame,
            anchor="nw"
        )

        # Keeps the inner frame synced with the canvas width when the window resizes.
        # This prevents clipping and weird left/right layout issues.
        def resize_main_frame(event):
            main_canvas.itemconfig(self.canvas_window, width=event.width)

        main_canvas.bind("<Configure>", resize_main_frame)

        main_canvas.configure(yscrollcommand=main_scrollbar.set)

        main_canvas.pack(side="left", fill="both", expand=True)
        main_scrollbar.pack(side="right", fill="y")

        tk.Label(
            self.main_frame,
            text="Secure Password Generator",
            font=("Arial", 18, "bold")
        ).pack(pady=10)

        tk.Label(
            self.main_frame,
            text="Generate passwords or passphrases, copy safely, and export for password manager import.",
            font=("Arial", 10),
            wraplength=650
        ).pack(pady=4)

        # -------------------------
        # Settings
        # -------------------------

        settings_frame = tk.Frame(self.main_frame)
        settings_frame.pack(pady=8, fill="x")

        tk.Label(settings_frame, text="Password Length:").grid(row=0, column=0, sticky="w", padx=5, pady=4)
        tk.Spinbox(settings_frame, from_=8, to=128, textvariable=self.length_var, width=8).grid(row=0, column=1, padx=5)

        tk.Label(settings_frame, text="Number to Generate:").grid(row=1, column=0, sticky="w", padx=5, pady=4)
        tk.Spinbox(settings_frame, from_=1, to=100, textvariable=self.count_var, width=8).grid(row=1, column=1, padx=5)

        tk.Label(settings_frame, text="Passphrase Words:").grid(row=2, column=0, sticky="w", padx=5, pady=4)
        tk.Spinbox(settings_frame, from_=3, to=12, textvariable=self.words_var, width=8).grid(row=2, column=1, padx=5)

        # -------------------------
        # Mode + Character Options
        # -------------------------

        options_container = tk.Frame(self.main_frame)
        options_container.pack(pady=6, fill="x")

        mode_frame = tk.LabelFrame(options_container, text="Mode", padx=15, pady=8)
        mode_frame.grid(row=0, column=0, padx=10, sticky="n")

        tk.Checkbutton(
            mode_frame,
            text="Passphrase Mode",
            variable=self.passphrase_mode_var
        ).pack(anchor="w")

        options_frame = tk.LabelFrame(
            options_container,
            text="Password Character Options",
            padx=15,
            pady=8
        )
        options_frame.grid(row=0, column=1, padx=10, sticky="n")

        tk.Checkbutton(options_frame, text="Uppercase Letters", variable=self.upper_var).pack(anchor="w")
        tk.Checkbutton(options_frame, text="Lowercase Letters", variable=self.lower_var).pack(anchor="w")
        tk.Checkbutton(options_frame, text="Numbers", variable=self.numbers_var).pack(anchor="w")
        tk.Checkbutton(options_frame, text="Symbols", variable=self.symbols_var).pack(anchor="w")

        tk.Checkbutton(
            options_frame,
            text="Avoid confusing characters: O, 0, I, l, 1",
            variable=self.ambiguous_var
        ).pack(anchor="w")

        # -------------------------
        # Buttons
        # -------------------------

        button_frame = tk.Frame(self.main_frame)
        button_frame.pack(pady=12, fill="x")

        # Even column spacing
        for col in range(4):
            button_frame.grid_columnconfigure(col, weight=1)

        # Row 1
        self.make_button(button_frame, "Generate", self.generate_items, 0, 0)
        self.make_button(button_frame, "Copy Selected", self.copy_selected, 0, 1)
        self.make_button(button_frame, "Copy All", self.copy_all, 0, 2)
        self.make_button(button_frame, "Select All", self.select_all, 0, 3)

        # Row 2
        self.make_button(button_frame, "Uncheck All", self.clear_selection, 1, 0)
        self.make_button(button_frame, "Clear Results", self.secure_clear_results, 1, 1)
        self.make_button(button_frame, "Clear Clipboard", self.clear_clipboard, 1, 2)
        self.make_button(button_frame, "Export CSV", self.export_password_manager_csv, 1, 3)


        # -------------------------
        # Custom Password Checker
        # -------------------------

        checker_frame = tk.LabelFrame(self.main_frame, text="Check Your Own Password", padx=10, pady=8)
        checker_frame.pack(pady=6, fill="x", padx=30)

        tk.Entry(
            checker_frame,
            textvariable=self.custom_password_var,
            width=45,
            show="*"
        ).grid(row=0, column=0, padx=5, pady=5)

        tk.Button(
            checker_frame,
            text="Check Strength",
            command=self.check_custom_password,
            width=18
        ).grid(row=0, column=1, padx=5)

        self.custom_strength_label = tk.Label(
            checker_frame,
            text="Strength: Not checked",
            font=("Arial", 10, "bold")
        )
        self.custom_strength_label.grid(row=1, column=0, columnspan=2, sticky="w", padx=5)

        # -------------------------
        # Status
        # -------------------------

        self.status_label = tk.Label(
            self.main_frame,
            text="Clipboard auto-clears after 30 seconds when using copy buttons.",
            font=("Arial", 9),
            wraplength=650
        )
        self.status_label.pack(pady=5)

        # -------------------------
        # Scrollable Results
        # -------------------------

        self.results_frame = tk.LabelFrame(self.main_frame, text="Generated Results", padx=8, pady=8)
        self.results_frame.pack(pady=8, fill="both", expand=True, padx=30)

        self.results_canvas = tk.Canvas(self.results_frame, height=250)
        self.results_scrollbar = tk.Scrollbar(
            self.results_frame,
            orient="vertical",
            command=self.results_canvas.yview
        )

        self.scrollable_frame = tk.Frame(self.results_canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda event: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all"))
        )

        self.results_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.results_canvas.configure(yscrollcommand=self.results_scrollbar.set)

        self.results_canvas.pack(side="left", fill="both", expand=True)
        self.results_scrollbar.pack(side="right", fill="y")

        tk.Label(
            self.main_frame,
            text="Tip: Click a generated item to copy it, or check multiple rows and use Copy Selected.",
            font=("Arial", 9),
            wraplength=650
        ).pack(pady=5)

    # =====================================================
    # Password Checker
    # =====================================================

    def check_custom_password(self):
        """Check strength of user-entered password."""
        password = self.custom_password_var.get()

        if not password:
            messagebox.showwarning("No Password", "Enter a password to check.")
            return

        pool_size = 0

        if any(char.isupper() for char in password):
            pool_size += 26

        if any(char.islower() for char in password):
            pool_size += 26

        if any(char.isdigit() for char in password):
            pool_size += 10

        if any(char in SYMBOLS for char in password):
            pool_size += len(SYMBOLS)

        if pool_size == 0:
            pool_size = 1

        strength, entropy = estimate_strength(password, pool_size)

        self.custom_strength_label.config(
            text=f"Strength: {strength} ({entropy:.1f} bits)",
            fg=strength_color(strength)
        )

    # =====================================================
    # Generation
    # =====================================================

    def clear_result_widgets(self):
        """Clear generated result rows from the UI."""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        self.check_vars = []

    def generate_items(self):
        """Generate passwords or passphrases."""
        self.secure_clear_memory_only()
        self.clear_result_widgets()

        try:
            count = int(self.count_var.get())
            passphrase_mode_enabled = self.passphrase_mode_var.get()

            for index in range(1, count + 1):
                if passphrase_mode_enabled:
                    item, strength, entropy = generate_passphrase(
                        word_count=int(self.words_var.get()),
                        add_upper=self.upper_var.get(),
                        add_lower=self.lower_var.get(),
                        add_number=self.numbers_var.get(),
                        add_symbol=self.symbols_var.get(),
                        avoid_ambiguous=self.ambiguous_var.get()
                    )
                else:
                    item, strength, entropy = generate_password(
                        length=int(self.length_var.get()),
                        use_upper=self.upper_var.get(),
                        use_lower=self.lower_var.get(),
                        use_numbers=self.numbers_var.get(),
                        use_symbols=self.symbols_var.get(),
                        avoid_ambiguous=self.ambiguous_var.get()
                    )

                self.generated_items.append(item)

                selected_var = tk.BooleanVar(value=False)
                self.check_vars.append(selected_var)

                row = tk.Frame(self.scrollable_frame)
                row.pack(anchor="w", fill="x", pady=3)

                tk.Checkbutton(row, variable=selected_var).pack(side="left")

                item_label = tk.Label(
                    row,
                    text=f"{index}. {item}",
                    font=("Courier", 11),
                    anchor="w",
                    width=42,
                    cursor="hand2"
                )
                item_label.pack(side="left", padx=8)

                item_label.bind("<Button-1>", lambda event, value=item: self.copy_single(value))

                tk.Label(
                    row,
                    text=f"{strength} ({entropy:.1f} bits)",
                    font=("Arial", 10, "bold"),
                    fg=strength_color(strength),
                    anchor="w"
                ).pack(side="left", padx=8)

            mode_name = "passphrase(s)" if passphrase_mode_enabled else "password(s)"
            self.status_label.config(text=f"Generated {count} {mode_name}.")

        except ValueError as error:
            messagebox.showerror("Error", str(error))

    # =====================================================
    # Selection Controls
    # =====================================================

    def select_all(self):
        """Check all generated items."""
        for var in self.check_vars:
            var.set(True)

    def clear_selection(self):
        """Uncheck all generated items."""
        for var in self.check_vars:
            var.set(False)

    def get_selected_items(self):
        """Return selected generated items."""
        return [
            self.generated_items[index]
            for index, var in enumerate(self.check_vars)
            if var.get()
        ]

    # =====================================================
    # Clipboard
    # =====================================================

    def copy_to_clipboard(self, items, message):
        """Copy items to clipboard and start the 30-second countdown."""
        if not items:
            messagebox.showwarning("Nothing Selected", "No items available to copy.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(items))
        self.root.update()

        self.status_label.config(
            text=f"{message} Clipboard clears in 30 seconds. Already pasted content cannot be removed."
        )

        self.start_clipboard_countdown()


    def start_clipboard_countdown(self):
        """Start or restart clipboard countdown."""
        if self.clipboard_timer_id is not None:
            self.root.after_cancel(self.clipboard_timer_id)
            self.clipboard_timer_id = None

        self.clipboard_seconds_remaining = 30
        self.update_clipboard_countdown()


    def update_clipboard_countdown(self):
        """Update countdown every second."""
        if self.clipboard_seconds_remaining <= 0:
            self.clear_clipboard(cancel_timer=False)
            return

        self.status_label.config(
            text=f"Clipboard clears in {self.clipboard_seconds_remaining} seconds. Already pasted content cannot be removed."
        )

        self.clipboard_seconds_remaining -= 1

        self.clipboard_timer_id = self.root.after(
            1000,
            self.update_clipboard_countdown
        )


    def clear_clipboard(self, cancel_timer=True):
        """Overwrite and clear clipboard."""
        if cancel_timer and self.clipboard_timer_id is not None:
            self.root.after_cancel(self.clipboard_timer_id)
            self.clipboard_timer_id = None

        self.root.clipboard_clear()
        self.root.clipboard_append("Clipboard cleared")
        self.root.update()

        self.root.clipboard_clear()
        self.root.update()

        self.status_label.config(
            text="Clipboard cleared. Already pasted content cannot be removed."
        )

    def copy_single(self, item):
        """Copy one clicked item."""
        self.copy_to_clipboard([item], "One item copied.")

    def copy_selected(self):
        """Copy selected items."""
        selected = self.get_selected_items()

        if not selected:
            messagebox.showwarning("No Selection", "Check one or more items first.")
            return

        self.copy_to_clipboard(selected, "Selected item(s) copied.")

    def copy_all(self):
        """Copy all generated items."""
        if not self.generated_items:
            messagebox.showwarning("No Results", "Generate items first.")
            return

        self.copy_to_clipboard(self.generated_items, "All item(s) copied.")

    def start_clipboard_countdown(self):
        """Start clipboard countdown."""
        if self.clipboard_timer_id:
            self.root.after_cancel(self.clipboard_timer_id)

        self.clipboard_seconds_remaining = self.clipboard_clear_after_ms // 1000
        self.update_clipboard_countdown()

    def update_clipboard_countdown(self):
        """Update countdown label every second."""
        if self.clipboard_seconds_remaining <= 0:
            self.clear_clipboard()
            self.clipboard_timer_id = None
            return

        self.status_label.config(
            text=f"Clipboard clears in {self.clipboard_seconds_remaining} seconds. Already pasted content cannot be removed."
        )

        self.clipboard_seconds_remaining -= 1
        self.clipboard_timer_id = self.root.after(1000, self.update_clipboard_countdown)

    def clear_clipboard(self):
        # Clipboard security note:
        # This clears the system clipboard, but it cannot remove text already pasted
        # into another app or stored by clipboard manager software.
        self.root.clipboard_clear()
        self.root.clipboard_append("Clipboard cleared")
        self.root.update()

        self.root.clipboard_clear()
        self.root.update()

        self.status_label.config(text="Clipboard cleared. Already pasted content cannot be removed.")

    # =====================================================
    # Clear + Export
    # =====================================================

    # Best-effort memory clearing.
    # Python strings are immutable, so this does not guarantee low-level memory wiping.
    # It does remove generated values from the app's active lists.
    def secure_clear_memory_only(self):
        for index in range(len(self.generated_items)):
            self.generated_items[index] = ""

        self.generated_items.clear()
        self.check_vars.clear()

    def secure_clear_results(self):
        """Clear generated results and clipboard."""
        self.secure_clear_memory_only()
        self.clear_result_widgets()
        self.clear_clipboard()
        self.status_label.config(text="Results and clipboard cleared.")

    # CSV export is provided for password manager import.
    # Security warning: CSV files are plain text. Delete the file after import.
    def export_password_manager_csv(self):
        if not self.generated_items:
            messagebox.showwarning("No Results", "Generate items first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Password Manager CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )

        if not file_path:
            return

        site_name = simpledialog.askstring(
            "Password Manager Export",
            "Enter a label/site name for these generated passwords:"
        )

        if not site_name:
            site_name = "Generated Password"

        # SECURITY WARNING:
        # Exported CSV files are not encrypted.
        # Import the file into a password manager immediately, then delete the CSV.
        with open(file_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["name", "username", "password", "url", "notes"])

            for index, item in enumerate(self.generated_items, start=1):
                writer.writerow([
                    f"{site_name} {index}",
                    "",
                    item,
                    "",
                    f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}"
                ])

        messagebox.showinfo(
            "Export Complete",
            "CSV exported. Import it into a password manager, then delete the CSV."
        )


def main():
    root = tk.Tk()
    PasswordGeneratorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
