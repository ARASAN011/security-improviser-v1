import requests
import hashlib
import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import os

# ---------------------------------------------------------
# ML SETUP
# ---------------------------------------------------------
data = {
    "email_text": [
        "Your password is expiring soon. Click the link to update.",
        "Verify your account immediately or it will be suspended.",
        "Meeting scheduled at 3 PM today.",
        "Attached is your invoice. Please review.",
        "We detected unusual activity. Login to secure your account.",
        "Lunch at 1 PM? Let me know.",
    ],
    "label": ["phishing", "phishing", "legit", "legit", "phishing", "legit"]
}

df = pd.DataFrame(data)

vectorizer = TfidfVectorizer(stop_words="english")
X = vectorizer.fit_transform(df["email_text"])
y = df["label"].map({"legit": 0, "phishing": 1})

model = LogisticRegression()
model.fit(X, y)

# ---------------------------------------------------------
# CONFIG - LOAD API KEY SAFELY
# ---------------------------------------------------------
HIBP_API_KEY = os.environ.get("HIBP_API_KEY")

HEADERS = {
    "hibp-api-key": HIBP_API_KEY if HIBP_API_KEY else "",
    "User-Agent": "PhishingScanner"
}

# Terminal Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ---------------------------------------------------------
# EMAIL BREACH CHECK
# ---------------------------------------------------------
def check_email_breach(email):
    if not HIBP_API_KEY:
        return False, ["API key missing"]

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        r = requests.get(url, headers=HEADERS)
        if r.status_code == 200:
            breaches = [b['Name'] for b in r.json()]
            return True, breaches
        if r.status_code == 404:
            return False, []
        return False, ["API error"]
    except:
        return False, ["Network error"]

# ---------------------------------------------------------
# PASSWORD BREACH CHECK (HIBP K-Anonymity)
# ---------------------------------------------------------
def check_password_breach(password):
    if not password:
        return False, 0

    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return False, 0
        for line in r.text.splitlines():
            p_hash, count = line.split(":")
            if p_hash == suffix:
                return True, int(count)
        return False, 0
    except:
        return False, 0

# ---------------------------------------------------------
# MOBILE BREACH CHECK (SIMULATED)
# ---------------------------------------------------------
SIMULATED_MOBILES = {"1234567890", "919876543210"}

def check_mobile_breach(mobile):
    if not mobile:
        return False
    clean = re.sub(r"\D", "", mobile)
    return clean in SIMULATED_MOBILES

# ---------------------------------------------------------
# MASTER CHECKER
# ---------------------------------------------------------
def check_live_breaches(email, password=None, mobile=None):
    email_breached, e_list = check_email_breach(email)
    pass_breached, pass_count = check_password_breach(password)
    mobile_breached = check_mobile_breach(mobile)

    return {
        "email_breached": email_breached,
        "email_breach_list": e_list,
        "password_breached": pass_breached,
        "password_appearance": pass_count,
        "mobile_breached": mobile_breached,
        "overall": any([email_breached, pass_breached, mobile_breached])
    }


# ---------------------------------------------------------
# RISK BAR
# ---------------------------------------------------------
def risk_bar(value):
    filled = int(value * 20)
    bar = f"{RED}{'█'*filled}{RESET}{'░'*(20-filled)}"
    return f"[{bar}] {int(value*100)}%"

# ---------------------------------------------------------
# FINAL ANALYSIS + OUTPUT
# ---------------------------------------------------------
def analyze(email_text, sender_email, user_email=None, password=None, mobile=None):
    features = vectorizer.transform([email_text])
    phishing_prob = round(model.predict_proba(features)[0][1], 3)

    # Live breaches check
    breaches = check_live_breaches(sender_email, password, mobile)
    
    # Optional: user email check
    if user_email:
        user_email_breached, user_breaches_list = check_email_breach(user_email)
    else:
        user_email_breached, user_breaches_list = False, []

    risk = "HIGH RISK" if phishing_prob > 0.6 or breaches["overall"] or user_email_breached else "SAFE"
    color = RED if risk == "HIGH RISK" else GREEN

    os.system("cls" if os.name == "nt" else "clear")

    print(f"{MAGENTA}{BOLD}\n===================================================")
    print("             PHISHING & BREACH DETECTION REPORT")
    print("===================================================\n" + RESET)

    print(f"{BOLD}Sender Email:{RESET} {sender_email}")
    print(f"{BOLD}User Email Checked:{RESET} {user_email if user_email else 'N/A'}")
    print(f"{BOLD}Phishing Probability:{RESET} {risk_bar(phishing_prob)}\n")

    print(f"{BOLD}--- Sender Breach Scan ---{RESET}")
    print(f"Email Breached:       {'YES' if breaches['email_breached'] else 'NO'}")
    print(f"Password Breached:    {'YES' if breaches['password_breached'] else 'NO'}")
    print(f"Mobile Breached:      {'YES' if breaches['mobile_breached'] else 'NO'}\n")

    if breaches["email_breached"]:
        print(f"{YELLOW}Breached Sites:{RESET}")
        for b in breaches["email_breach_list"]:
            print(f"  - {b}")
        print()

    if breaches["password_breached"]:
        print(f"{RED}Password exposed {breaches['password_appearance']} times!{RESET}\n")

    if user_email_breached:
        print(f"{YELLOW}{BOLD}User Email Breached:{RESET}")
        for b in user_breaches_list:
            print(f"  - {b}")
        print()

    print(f"{BOLD}---------------------------------------------------{RESET}")
    print(f"FINAL RISK LEVEL: {color}{BOLD}{risk}{RESET}")
    print(f"{BOLD}---------------------------------------------------\n{RESET}")

# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------
if name == "main":
    print("====== LIVE PHISHING & BREACH DETECTOR ======")

    email_text = input("\nEnter email content: ")
    sender = input("Sender email: ")
    user_email = input("Your email to check (optional): ")
    password = input("Password (optional): ")
    mobile = input("Mobile number (optional): ")

    analyze(email_text, sender, user_email, password, mobile)