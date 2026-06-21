import streamlit as st
import math
import re
import string
import secrets
import random

st.set_page_config(page_title="Password Strength Checker", page_icon="🔒", layout="centered")

WEAK_PASSWORDS = {
    "password", "123456", "password1", "qwerty", "abc123", "letmein",
    "monkey", "1234567890", "iloveyou", "admin", "welcome", "login",
    "master", "hello", "dragon", "pass", "shadow", "superman", "michael",
    "football", "baseball", "soccer", "princess", "starwars", "password123",
    "654321", "trustno1", "000000", "111111", "sunshine", "access", "batman",
    "test", "user", "root"
}

def has_keyboard_pattern(pwd):
    patterns = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "123456", "654321"]
    lower = pwd.lower()
    for p in patterns:
        if p in lower:
            return True
    return False

def is_all_same_char(pwd):
    return len(set(pwd)) == 1

def check_password(pwd):
    if not pwd:
        return None

    score = 0
    feedback = []
    length = len(pwd)

    if length < 6:
        feedback.append("Too short, use at least 8 characters")
    elif length < 8:
        feedback.append("A bit short, try going over 8 characters")
        score += 5
    elif length < 12:
        score += 15
    elif length < 16:
        score += 25
    else:
        score += 35

    has_lower = bool(re.search(r'[a-z]', pwd))
    has_upper = bool(re.search(r'[A-Z]', pwd))
    has_num   = bool(re.search(r'[0-9]', pwd))
    has_sym   = bool(re.search(r'[^a-zA-Z0-9]', pwd))

    if has_lower: score += 10
    else: feedback.append("Add some lowercase letters")

    if has_upper: score += 10
    else: feedback.append("Mix in some uppercase letters")

    if has_num: score += 10
    else: feedback.append("Include at least one number")

    if has_sym: score += 15
    else: feedback.append("Special characters like !@#$ help a lot")

    is_common = pwd.lower() in WEAK_PASSWORDS
    if is_common:
        score = min(score, 8)
        feedback.append("This is one of the most common passwords, change it")

    if is_all_same_char(pwd):
        score = max(0, score - 20)
        feedback.append("All same character doesn't count as variety")

    if has_keyboard_pattern(pwd):
        score = max(0, score - 15)
        feedback.append("Keyboard patterns like qwerty are cracked instantly")

    unique_chars = len(set(pwd))
    ratio = unique_chars / length

    if ratio < 0.4:
        feedback.append("Too many repeated characters")
        score = max(0, score - 10)
    elif ratio > 0.75:
        score += 5

    score = min(100, max(0, score))

    if score < 20:   label, color = "Very Weak",  "#e74c3c"
    elif score < 40: label, color = "Weak",        "#e67e22"
    elif score < 60: label, color = "Moderate",    "#f1c40f"
    elif score < 80: label, color = "Strong",      "#2ecc71"
    else:            label, color = "Very Strong", "#27ae60"

    charset = 0
    if has_lower: charset += 26
    if has_upper: charset += 26
    if has_num:   charset += 10
    if has_sym:   charset += 30
    entropy = round(math.log2(charset) * length, 1) if charset > 0 else 0

    return {
        "score": score, "label": label, "color": color,
        "feedback": feedback, "has_lower": has_lower, "has_upper": has_upper,
        "has_num": has_num, "has_sym": has_sym, "length": length,
        "unique_chars": unique_chars, "entropy": entropy, "is_common": is_common
    }

def estimate_crack_time(entropy):
    if entropy == 0: return "instantly"
    seconds = (2 ** entropy) / 10_000_000_000
    if seconds < 1:        return "instantly"
    if seconds < 60:       return f"about {int(seconds)} second(s)"
    if seconds < 3600:     return f"about {int(seconds/60)} minute(s)"
    if seconds < 86400:    return f"about {int(seconds/3600)} hour(s)"
    if seconds < 31536000: return f"about {int(seconds/86400)} day(s)"
    if seconds < 3.15e9:   return f"about {int(seconds/31536000)} year(s)"
    return "centuries"

def make_strong_password():
    lower   = string.ascii_lowercase
    upper   = string.ascii_uppercase
    digits  = string.digits
    symbols = "!@#$%&*?"
    all_chars = lower + upper + digits + symbols
    pwd = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    for _ in range(12):
        pwd.append(secrets.choice(all_chars))
    random.shuffle(pwd)
    return "".join(pwd)

st.markdown("""
<style>
.badge-pass { background:#d4edda; color:#155724; padding:3px 10px; border-radius:20px; font-size:13px; margin:3px; display:inline-block; }
.badge-fail { background:#f8d7da; color:#721c24; padding:3px 10px; border-radius:20px; font-size:13px; margin:3px; display:inline-block; }
.alt-box { background:#f7f8fa; border:1px solid #ddd; border-radius:8px; padding:10px 14px; margin-bottom:8px; font-size:14px; font-family:monospace; }
.warn-box { background:#fff3cd; border:1px solid #ffc107; border-radius:8px; padding:10px 14px; color:#856404; font-size:13px; }
</style>
""", unsafe_allow_html=True)

if "history" not in st.session_state:
    st.session_state.history = []

st.markdown("## 🔒 Password Strength Checker")
st.markdown("Check how strong your password is and get tips to improve it.")
st.divider()

col1, col2 = st.columns([3, 1])
with col1:
    password = st.text_input("Enter your password", type="password", placeholder="Type a password...")
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("⚡ Generate", use_container_width=True):
        st.session_state["generated"] = make_strong_password()

if "generated" in st.session_state and st.session_state["generated"]:
    st.info(f"Generated: `{st.session_state['generated']}`")
    st.caption("Copy the above and paste it in the input field.")

if st.checkbox("Show password") and password:
    st.code(password)

if st.button("💾 Save to History", disabled=not password):
    if password not in st.session_state.history:
        st.session_state.history.append(password)
        st.success("Saved!")
    else:
        st.warning("Already saved.")

if password and password in st.session_state.history:
    st.markdown('<div class="warn-box">⚠️ You have used this password before. Avoid reusing passwords.</div>', unsafe_allow_html=True)

st.divider()

result = check_password(password)

if result:
    st.markdown(f"### Strength: <span style='color:{result['color']}'>{result['label']}</span>", unsafe_allow_html=True)
    st.progress(result["score"] / 100)
    st.caption(f"Score: {result['score']} / 100")

    c1, c2, c3 = st.columns(3)
    c1.metric("Length", result["length"])
    c2.metric("Entropy", f"{result['entropy']} bits")
    c3.metric("Unique Chars", result["unique_chars"])

    st.info(f"⏱️ Estimated crack time (GPU attack): **{estimate_crack_time(result['entropy'])}**")

    badges = ""
    badges += f'<span class="{"badge-pass" if result["has_lower"] else "badge-fail"}">{"✓" if result["has_lower"] else "✗"} Lowercase</span>'
    badges += f'<span class="{"badge-pass" if result["has_upper"] else "badge-fail"}">{"✓" if result["has_upper"] else "✗"} Uppercase</span>'
    badges += f'<span class="{"badge-pass" if result["has_num"] else "badge-fail"}">{"✓" if result["has_num"] else "✗"} Numbers</span>'
    badges += f'<span class="{"badge-pass" if result["has_sym"] else "badge-fail"}">{"✓" if result["has_sym"] else "✗"} Symbols</span>'
    st.markdown(badges, unsafe_allow_html=True)
    st.markdown("")

    if result["feedback"]:
        st.markdown("**Things to fix:**")
        for tip in result["feedback"]:
            st.markdown(f"- {tip}")
    else:
        st.success("✅ No obvious issues found.")

if st.session_state.history:
    st.divider()
    st.markdown(f"#### 🕓 Password History ({len(st.session_state.history)})")
    for h in st.session_state.history:
        st.caption(f"{'● ' * min(len(h), 16)}  ({len(h)} chars)")
    st.caption("Passwords are masked. Re-entering a saved one will trigger a warning.")