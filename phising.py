import streamlit as st
import pandas as pd
import numpy as np
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(page_title="Phishing Email Detector", page_icon="📧", layout="centered")

# ---- sample dataset ----
# 1 = phishing, 0 = safe
EMAILS = [
    ("Congratulations! You have won a $1000 gift card. Click here to claim now!", 1),
    ("Verify your account immediately or it will be suspended. Login here.", 1),
    ("Dear user, your PayPal account has been limited. Confirm your identity now.", 1),
    ("You have been selected for a special prize. Enter your details to win.", 1),
    ("URGENT: Your bank account needs verification. Click the link below.", 1),
    ("Free iPhone giveaway! You are the lucky winner. Claim your prize now.", 1),
    ("Your password will expire in 24 hours. Update it immediately at this link.", 1),
    ("Alert: Suspicious login detected. Verify your account to avoid suspension.", 1),
    ("You owe taxes. Pay immediately to avoid legal action. Click here.", 1),
    ("Dear customer, your Amazon order is on hold. Confirm payment details.", 1),
    ("Act now! Limited time offer. Get rich working from home. Sign up free.", 1),
    ("Your Netflix account has been suspended. Update billing information now.", 1),
    ("Security alert: Your email was accessed from unknown location. Verify now.", 1),
    ("Win a free vacation! You have been chosen. Provide your details today.", 1),
    ("Urgent action required: Your Apple ID has been locked. Verify immediately.", 1),
    ("Click here to receive your inheritance payment of $5 million dollars.", 1),
    ("Your account will be deleted unless you confirm your details in 12 hours.", 1),
    ("Exclusive offer for you only. Earn $500 daily from home. No experience needed.", 1),
    ("Warning: Your computer has a virus. Download our antivirus software now.", 1),
    ("Congratulations you have been pre-approved for a loan of $50000 apply now.", 1),
    ("Dear friend, I need your help to transfer funds. You will get 30 percent.", 1),
    ("Your DHL package is on hold. Pay the delivery fee now to release it.", 1),
    ("Verify your Google account immediately. Unusual activity was detected.", 1),
    ("You are a winner of our weekly lottery. Claim your $10000 prize today.", 1),
    ("Important: Update your credit card information to continue using services.", 1),
    ("Hi team, the meeting has been rescheduled to 3pm tomorrow. Please confirm.", 0),
    ("Please find attached the project report for Q3. Let me know your feedback.", 0),
    ("Hey, are you free this weekend? We should catch up for coffee sometime.", 0),
    ("Reminder: Your dentist appointment is on Friday at 10am. Call to reschedule.", 0),
    ("Thanks for your order! Your package will arrive between Monday and Wednesday.", 0),
    ("Your monthly bank statement is now available. Login to view your balance.", 0),
    ("Hi, I wanted to follow up on our discussion from last week regarding the project.", 0),
    ("The team lunch is confirmed for Thursday. We will meet at the usual place.", 0),
    ("Your subscription has been renewed successfully. Thank you for staying with us.", 0),
    ("Please review the attached document and share your comments by end of week.", 0),
    ("Good morning, just checking in on the status of the report due next Monday.", 0),
    ("Your flight booking is confirmed. Check-in opens 24 hours before departure.", 0),
    ("We wanted to let you know your return has been processed and refund issued.", 0),
    ("Hello, I came across your profile and would love to connect professionally.", 0),
    ("Your electricity bill for this month is ready. Due date is the 15th.", 0),
    ("Thanks for attending the webinar. Here are the slides from today's session.", 0),
    ("Your library book is due back next week. Renew online to avoid late fees.", 0),
    ("Happy birthday! Wishing you a great day filled with joy and celebration.", 0),
    ("The software update has been successfully installed on your device.", 0),
    ("Please complete the feedback form for our service. It takes only 2 minutes.", 0),
    ("Your job application has been received. We will be in touch within 5 days.", 0),
    ("Good news, your insurance claim has been approved. Payment within 3 days.", 0),
    ("The quarterly budget meeting is scheduled for next Tuesday at 2pm.", 0),
    ("Your gym membership has been renewed. See you at the next class!", 0),
    ("Hi, just a reminder to submit your timesheet before end of day Friday.", 0),
]

# ---- feature extraction ----
def extract_features(text):
    features = {}
    features["has_urgent_words"] = int(bool(re.search(
        r'\b(urgent|immediately|verify|suspend|limited|action required|click now|act now|winner|congratulations|free|prize|claim)\b',
        text.lower()
    )))
    features["has_url_words"] = int(bool(re.search(
        r'\b(click here|login|link|http|www|verify|update|confirm)\b',
        text.lower()
    )))
    features["has_money_words"] = int(bool(re.search(
        r'\b(win|won|prize|reward|cash|dollar|money|payment|loan|earn|rich|free)\b',
        text.lower()
    )))
    features["exclamation_count"] = text.count("!")
    features["uppercase_ratio"] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    features["word_count"] = len(text.split())
    features["has_numbers"] = int(bool(re.search(r'\d+', text)))
    return features

# ---- build dataframe ----
@st.cache_data
def load_data():
    texts = [e[0] for e in EMAILS]
    labels = [e[1] for e in EMAILS]

    # extract manual features
    feat_list = [extract_features(t) for t in texts]
    feat_df = pd.DataFrame(feat_list)

    return texts, labels, feat_df

# ---- train model ----
@st.cache_resource
def train_model():
    texts, labels, feat_df = load_data()

    # tfidf on text
    vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
    tfidf_matrix = vectorizer.fit_transform(texts).toarray()
    tfidf_df = pd.DataFrame(tfidf_matrix)

    # combine tfidf + manual features
    X = np.hstack([tfidf_df.values, feat_df.values])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Safe", "Phishing"])

    return model, vectorizer, acc, cm, report

# ---- predict single email ----
def predict_email(text, model, vectorizer):
    tfidf = vectorizer.transform([text]).toarray()
    feats = pd.DataFrame([extract_features(text)]).values
    X = np.hstack([tfidf, feats])
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0]
    return pred, prob


# ======================================================
# UI
# ======================================================

st.markdown("""
<style>
.phish-box { background:#f8d7da; border:1px solid #f5c6cb; border-radius:10px; padding:16px; color:#721c24; font-size:15px; }
.safe-box  { background:#d4edda; border:1px solid #c3e6cb; border-radius:10px; padding:16px; color:#155724; font-size:15px; }
.info-box  { background:#f7f8fa; border:1px solid #ddd; border-radius:10px; padding:14px; font-size:13px; }
</style>
""", unsafe_allow_html=True)

st.markdown("## 📧 Phishing Email Detector")
st.markdown("A machine learning model that classifies emails as **Phishing** or **Safe**.")
st.divider()

# train on load
with st.spinner("Training model on dataset..."):
    model, vectorizer, acc, cm, report = train_model()

# model stats
st.markdown("#### Model Performance")
c1, c2, c3 = st.columns(3)
c1.metric("Accuracy", f"{acc * 100:.1f}%")
c2.metric("Algorithm", "Random Forest")
c3.metric("Training Emails", len(EMAILS))

# confusion matrix
st.markdown("#### Confusion Matrix")
fig, ax = plt.subplots(figsize=(5, 3))
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Safe", "Phishing"],
    yticklabels=["Safe", "Phishing"],
    ax=ax
)
ax.set_xlabel("Predicted")
ax.set_ylabel("Actual")
ax.set_title("Confusion Matrix")
st.pyplot(fig)

# classification report
with st.expander("Show detailed classification report"):
    st.code(report)

st.divider()

# email classifier
st.markdown("#### Test the Model")
st.markdown("Paste any email text below to check if it's phishing or safe.")

email_input = st.text_area(
    "Email content",
    placeholder="Paste email text here...",
    height=150
)

# quick test examples
st.caption("Or try a quick example:")
col1, col2 = st.columns(2)
with col1:
    if st.button("Load Phishing Example"):
        st.session_state["example"] = "Congratulations! You have won a $500 gift card. Click here immediately to claim your prize before it expires!"
with col2:
    if st.button("Load Safe Example"):
        st.session_state["example"] = "Hi team, please find the meeting notes attached. Let me know if you have any questions or feedback."

if "example" in st.session_state:
    email_input = st.session_state["example"]
    st.info(f"Loaded: *{email_input[:80]}...*")

if st.button("🔍 Analyze Email", type="primary", disabled=not email_input):
    pred, prob = predict_email(email_input, model, vectorizer)
    confidence = max(prob) * 100

    st.markdown("#### Result")
    if pred == 1:
        st.markdown(f"""
        <div class="phish-box">
        🚨 <b>PHISHING EMAIL DETECTED</b><br><br>
        This email shows signs of being a phishing attempt.<br>
        Confidence: <b>{confidence:.1f}%</b>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="safe-box">
        ✅ <b>SAFE EMAIL</b><br><br>
        This email appears to be legitimate.<br>
        Confidence: <b>{confidence:.1f}%</b>
        </div>
        """, unsafe_allow_html=True)

    # feature breakdown
    st.markdown("#### Why this result?")
    feats = extract_features(email_input)
    breakdown = {
        "Urgent/suspicious words found": "Yes ⚠️" if feats["has_urgent_words"] else "No ✅",
        "Click/login/link words found": "Yes ⚠️" if feats["has_url_words"] else "No ✅",
        "Money/prize words found": "Yes ⚠️" if feats["has_money_words"] else "No ✅",
        "Exclamation marks": feats["exclamation_count"],
        "Uppercase ratio": f"{feats['uppercase_ratio']*100:.1f}%",
        "Word count": feats["word_count"],
    }
    for k, v in breakdown.items():
        st.caption(f"**{k}:** {v}")

st.divider()
st.caption("Model trained on sample dataset for educational purposes.")
