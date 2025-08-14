import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from fpdf import FPDF  # PDF support

# --- Config ---

SUSPICIOUS_KEYWORDS = [
    "ransomware", "keylogger", "trojan", "stealer", "eicar",
    "base64.b64decode(", "subprocess", "os.system", "eval(", "exec(",
    "socket", "popen", "backdoor"
]

SECURITY_TIPS = [
    "1. Don’t open unknown attachments.",
    "2. Use strong, unique passwords.",
    "3. Keep software and antivirus updated.",
    "4. Avoid untrusted apps.",
    "5. Backup important data regularly."
]

BREACHED_DOMAINS = ["example.com", "mail.ru", "123.com", "hackmail.net"]

# --- Core Functions ---

def scan_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore').lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    return True, keyword
    except:
        return False, "Error reading file"
    return False, None

def is_email_safe(email):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False, "Invalid email format."
    
    domain = email.split("@")[1]
    if domain in BREACHED_DOMAINS:
        return False, f"Email domain '{domain}' is linked to past breaches."
    
    return True, "This email appears safe."

# --- GUI App ---

class SecureScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureScan Antivirus")
        self.root.geometry("650x500")
        self.root.resizable(False, False)

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(expand=1, fill='both')

        self.create_file_tab()
        self.create_email_tab()

    # --- File Scanner Tab ---
    def create_file_tab(self):
        self.file_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.file_tab, text="🔍 File Scanner")

        ttk.Label(self.file_tab, text="Scan a file for malicious patterns", font=("Segoe UI", 16)).pack(pady=10)

        self.path_entry = ttk.Entry(self.file_tab, width=70)
        self.path_entry.pack(pady=5)

        self.browse_btn = ttk.Button(self.file_tab, text="Select File", command=self.browse_file)
        self.browse_btn.pack()

        self.scan_btn = ttk.Button(self.file_tab, text="Scan File", command=self.start_file_scan)
        self.scan_btn.pack(pady=5)

        self.output_box = tk.Text(self.file_tab, height=12, width=80)
        self.output_box.pack(pady=10)

        self.tips_btn = ttk.Button(self.file_tab, text="Show Security Tips", command=self.show_tips)
        self.tips_btn.pack(pady=5)

        self.export_btn = ttk.Button(self.file_tab, text="Export Report", command=self.save_report)
        self.export_btn.pack(pady=5)

    # --- Email Checker Tab ---
    def create_email_tab(self):
        self.email_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.email_tab, text="📧 Email Checker")

        ttk.Label(self.email_tab, text="Check if an email address is safe", font=("Segoe UI", 16)).pack(pady=20)

        self.email_entry = ttk.Entry(self.email_tab, width=50)
        self.email_entry.pack(pady=5)

        self.check_email_btn = ttk.Button(self.email_tab, text="Check Email", command=self.check_email)
        self.check_email_btn.pack(pady=5)

        self.email_result = tk.Text(self.email_tab, height=8, width=60)
        self.email_result.pack(pady=10)

    # --- Functional Buttons ---
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, file_path)

    def start_file_scan(self):
        file_path = self.path_entry.get()
        self.output_box.delete('1.0', tk.END)

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "Invalid file selected.")
            return

        self.output_box.insert(tk.END, f"📄 Scanning file: {file_path}\n\n")
        infected, signature = scan_file(file_path)

        if infected:
            self.output_box.insert(tk.END, f"⚠ Threat Found: {signature}\n")
            messagebox.showwarning("Virus Detected", f"Suspicious content found in:\n{file_path}")
        else:
            self.output_box.insert(tk.END, "✅ No threats found.\n")

    def check_email(self):
        email = self.email_entry.get()
        self.email_result.delete('1.0', tk.END)

        safe, message = is_email_safe(email)
        if safe:
            messagebox.showinfo("Email Check", message)
            self.email_result.insert(tk.END, f"✅ {email} is safe.\n{message}")
        else:
            messagebox.showerror("Email Warning", message)
            self.email_result.insert(tk.END, f"⚠ {email} may be unsafe.\n{message}")

    def show_tips(self):
        tips = "\n".join(SECURITY_TIPS)
        messagebox.showinfo("Security Tips", tips)

    def save_report(self):
        content = self.output_box.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Empty Report", "Nothing to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt"), ("PDF File", "*.pdf")],
            title="Save Report"
        )
        if not file_path:
            return

        if file_path.endswith(".pdf"):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.set_font("Arial", size=12)
            for line in content.split("\n"):
                pdf.multi_cell(0, 10, line)
            pdf.output(file_path)
        else:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

        messagebox.showinfo("Saved", f"Report saved to:\n{file_path}")

# --- Launch App ---
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureScanApp(root)
    root.mainloop()
