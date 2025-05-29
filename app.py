
import streamlit as st
import pickle
import numpy as np
import matplotlib.pyplot as plt
import re
from urllib.parse import urlparse
from io import BytesIO
import base64
from fpdf import FPDF
import warnings

warnings.filterwarnings("ignore")
plt.rcParams.update({'font.size': 8})

# Load model and vectorizer
with open('phishing_model.pkl', 'rb') as f:
    tf, model = pickle.load(f)


def create_safety_meter(value, color):
    fig, ax = plt.subplots(figsize=(5, 1))
    ax.barh([" "], [value], color=color, height=0.3)
    ax.set_xlim(0, 1)
    ax.axis('off')
    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', transparent=True)
    plt.close(fig)
    return base64.b64encode(buf.getbuffer()).decode()


def generate_bar_plot(top_features):
    words, scores = zip(*top_features)
    fig, ax = plt.subplots()
    colors = ['#ff4b4b' if s > 0 else '#4bb543' for s in scores]
    ax.barh(words, scores, color=colors)
    ax.invert_yaxis()
    ax.set_xlabel("Importance Score")
    ax.set_title("Top Influential Words")
    fig.tight_layout()
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf


def generate_pdf_report(result, confidence, top_features, indicators):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    clean_result = "Phishing Email" if "Phishing" in result else "Legitimate Email"
    pdf.set_text_color(
        220, 50, 50) if "Phishing" in clean_result else pdf.set_text_color(50, 150, 50)
    pdf.cell(200, 10, txt=f"Result: {clean_result}", ln=True)

    pdf.set_text_color(0, 0, 0)
    pdf.cell(200, 10, txt=f"Confidence: {confidence*100:.2f}%", ln=True)

    pdf.cell(200, 10, txt="Top Features:", ln=True)
    for word, score in top_features:
        pdf.cell(200, 10, txt=f"{word}: {score:.4f}", ln=True)

    pdf.cell(200, 10, txt="Threat Indicators:", ln=True)
    for k, v in indicators.items():
        pdf.cell(200, 10, txt=f"{k}: {v}", ln=True)

    return bytes(pdf.output(dest='S'))  # ✅ return raw bytes


# UI
st.set_page_config(page_title="PhishGuard AI 🛡️", layout="wide")
st.title("PhishGuard AI 🕵️‍♂️")
st.markdown("Detect phishing emails with Machine Learning ⚔️")

with st.expander("📘 How It Works"):
    st.markdown("""
    1. Paste or upload an email.
    2. The system uses a trained ML model to classify the email.
    3. Extracts key features and security threats.
    4. Presents visual explanations and downloadable PDF reports.
    """)

email_text = st.text_area("📩 Paste the email content:", height=200)
uploaded_file = st.file_uploader("Or upload a .txt file", type=["txt"])

if uploaded_file:
    email_text = uploaded_file.read().decode("utf-8")

if st.button("🔍 Analyze Email"):
    if not email_text.strip():
        st.warning("Please enter or upload email content.")
    else:
        X_input = tf.transform([email_text])

        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_input)[0]
            confidence = np.max(proba)
            prediction = np.argmax(proba)
        else:
            prediction = model.predict(X_input)[0]
            confidence = 1.0

        result = "🛑 Phishing Email" if prediction == 0 else "✅ Legitimate Email"
        color = "#ff4b4b" if prediction == 0 else "#4bb543"
        safety_level = 1 - confidence if prediction == 1 else confidence

        links = re.findall(r'https?://\S+', email_text)
        indicators = {
            "Suspicious Links": len(links),
            "Urgency Keywords": len(re.findall(r"\burgent\b", email_text, re.IGNORECASE)),
            "Generic Greetings": any(x in email_text.lower() for x in ["dear user", "valued customer"]),
            "Misspelled Domains": sum(1 for link in links if any(c.isupper() for c in urlparse(link).netloc))
        }

        col1, col2 = st.columns(2)

        with col1:
            st.markdown(
                f"<h2 style='color:{color};'>{result}</h2>", unsafe_allow_html=True)
            st.progress(confidence)
            st.markdown(f"**Confidence:** `{confidence * 100:.2f}%`")

            st.markdown("### 🔑 Key Features")
            try:
                if hasattr(model, 'coef_'):
                    coefficients = model.coef_[0]
                    features = tf.get_feature_names_out()
                    top_features = sorted(
                        zip(features, coefficients), key=lambda x: abs(x[1]), reverse=True)[:10]
                elif hasattr(model, 'feature_importances_'):
                    importances = model.feature_importances_
                    features = tf.get_feature_names_out()
                    top_features = sorted(
                        zip(features, importances), key=lambda x: x[1], reverse=True)[:10]
                else:
                    top_features = []

                if top_features:
                    st.image(generate_bar_plot(
                        top_features), caption="Top Feature Importance", use_container_width=True)

            except Exception as e:
                st.warning(f"Feature extraction failed: {str(e)}")

            pdf_bytes = generate_pdf_report(
                result, confidence, top_features, indicators)
            b64_pdf = base64.b64encode(pdf_bytes).decode()
            href = f'<a href="data:application/octet-stream;base64,{b64_pdf}" download="phishguard_report.pdf">📄 Download PDF Report</a>'
            st.markdown(href, unsafe_allow_html=True)

        with col2:
            st.markdown("### 🔒 Security Analysis")
            st.markdown(f"#### 🔗 Detected Links ({len(links)})")
            if links:
                for link in links:
                    st.write("•", urlparse(link).netloc)
            else:
                st.write("No links found")

            st.markdown("#### 🎮 Email Safety Meter")
            safety_meter_img = create_safety_meter(safety_level, color)
            st.image(
                f"data:image/png;base64,{safety_meter_img}", use_container_width=True)

            st.markdown("#### 📊 Threat Breakdown")
            for k, v in indicators.items():
                st.write(f"**{k}:** {v}")

st.markdown("---")
st.caption("Created with ❤️ by your AI Assistant. Stay safe online!")
