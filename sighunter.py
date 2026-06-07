"""
SigHunter - Custom Threat Detection Rule Validator & Log Parser.
Designed for Tier-2 SOC analysts to visually test and verify Sigma/YARA alert triggers.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import re
import json

class SigHunterUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SigHunter Engine - Threat Rule Validator")
        self.root.geometry("900x700")
        self.root.configure(bg="#0f141c") # Ultra dark terminal slate theme

        # --- Top Header ---
        header = tk.Label(
            self.root, 
            text="SIGHUNTER: DETECTION RULE VALIDATION CONSOLE", 
            font=("Arial", 13, "bold"), 
            bg="#161d26", 
            fg="#38bdf8", # Cyan alert theme
            pady=12
        )
        header.pack(fill=tk.X)

        # --- Main Workspace Panel ---
        workspace = tk.Frame(self.root, bg="#0f141c", padx=15, pady=10)
        workspace.pack(fill=tk.BOTH, expand=True)

        # Left Frame: Inputs (Logs & Rules)
        left_frame = tk.Frame(workspace, bg="#0f141c")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        log_label = tk.Label(left_frame, text="1. Paste Raw System Log Payload (JSON or Text):", font=("Arial", 10, "bold"), bg="#0f141c", fg="#ffffff")
        log_label.pack(anchor=tk.W, pady=(0, 5))

        self.log_input = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, height=12, bg="#161d26", fg="#ffffff", insertbackground="white", font=("Courier", 10))
        self.log_input.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Load an interactive default Windows event log template
        default_log = (
            '{\n'
            '  "EventID": 4688,\n'
            '  "NewProcessName": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",\n'
            '  "CommandLine": "powershell.exe -nop -w hidden -encodedcommand JABjID0AJw...",\n'
            '  "User": "SYSTEM"\n'
            '}'
        )
        self.log_input.insert(tk.END, default_log)

        rule_label = tk.Label(left_frame, text="2. Define Alert Condition (Search String or Keyword):", font=("Arial", 10, "bold"), bg="#0f141c", fg="#ffffff")
        rule_label.pack(anchor=tk.W, pady=(0, 5))

        self.rule_input = tk.Entry(left_frame, bg="#161d26", fg="#38bdf8", insertbackground="white", font=("Courier", 11, "bold"))
        self.rule_input.pack(fill=tk.X, pady=(0, 5))
        self.rule_input.insert(0, "-encodedcommand")

        # Right Frame: Live Triage Validation Output
        right_frame = tk.Frame(workspace, bg="#0f141c")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        output_label = tk.Label(right_frame, text="Rule Test Results & Analysis:", font=("Arial", 10, "bold"), bg="#0f141c", fg="#ffffff")
        output_label.pack(anchor=tk.W, pady=(0, 5))

        self.output_feed = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, bg="#161d26", fg="#a7f3d0", font=("Courier", 10))
        self.output_feed.pack(fill=tk.BOTH, expand=True)
        self.output_feed.insert(tk.END, "[*] Ready for detection rule validation tracking script...")

        # --- Action Control Deck ---
        control_deck = tk.Frame(self.root, bg="#161d26", pady=12)
        control_deck.pack(fill=tk.X, side=tk.BOTTOM)

        test_btn = tk.Button(control_deck, text="VERIFY DETECTION MATCH", command=self.test_rule_match, bg="#38bdf8", fg="#0f141c", font=("Arial", 10, "bold"), activebackground="#0ea5e9", padx=20)
        test_btn.pack(side=tk.LEFT, padx=20)

        reset_btn = tk.Button(control_deck, text="Reset Engine", command=self.reset_console, bg="#374151", fg="#ffffff", font=("Arial", 10), activebackground="#1f2937", padx=15)
        reset_btn.pack(side=tk.RIGHT, padx=20)

    def reset_console(self):
        self.log_input.delete("1.0", tk.END)
        self.rule_input.delete(0, tk.END)
        self.output_feed.delete("1.0", tk.END)
        self.output_feed.insert(tk.END, "[*] Console fields reset. Awaiting log matching configuration parameters.")

    def test_rule_match(self):
        raw_log = self.log_input.get("1.0", tk.END).strip()
        target_rule = self.rule_input.get().strip()

        if not raw_log or not target_rule:
            messagebox.showwarning("Missing Parameter", "Please ensure both log samples and rule criteria values are populated.")
            return

        self.output_feed.delete("1.0", tk.END)
        
        # Check for matching rule constraints inside the log payload
        match_found = re.search(re.escape(target_rule), raw_log, re.IGNORECASE)

        report = []
        report.append("==================================================")
        report.append("         SIGHUNTER DETECTION RULE ANALYSIS        ")
        report.append("==================================================")
        
        if match_found:
            report.append("\n[🟢] DETECTION RULE MATCH VERIFIED!")
            report.append(f"    -> Trigger Criterion Found: '{target_rule}'")
            
            # Simple metadata categorization helper
            if "powershell" in raw_log.lower() and "-encodedcommand" in raw_log.lower():
                report.append("\n[!] MITRE ATT&CK Mapping: T1059.001 (Command and Scripting Interpreter: PowerShell)")
                report.append("[!] Attack Classification: Malicious Obfuscated Process Execution")
                report.append("[!] Severity Rating: HIGH")
            else:
                report.append("\n[!] Threat Classification: Generic Signature Hit")
                report.append("[!] Severity Rating: MEDIUM")
                
            report.append("\n[+] Recommended Containment Vector:")
            report.append("    Deploy EDR policy modification to terminate matching process tree strings immediately.")
        else:
            self.output_feed.config(fg="#fca5a5") # Turn text soft red for negative result
            report.append("\n[⚪] DETECTION RULE STATUS: NO MATCH")
            report.append(f"    -> The search string '{target_rule}' was not identified inside the provided log.")
            report.append("\n[*] Diagnostic Check:")
            report.append("    Verify spacing, uppercase/lowercase syntax rules, or JSON nesting keys to ensure visibility limits match properly.")

        self.output_feed.insert(tk.END, "\n".join(report))
        if match_found:
            self.output_feed.config(fg="#a7f3d0") # Maintain positive green alert font

if __name__ == "__main__":
    app_window = tk.Tk()
    engine = SigHunterUI(app_window)
    app_window.mainloop()

