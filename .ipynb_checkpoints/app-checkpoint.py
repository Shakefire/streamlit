
import streamlit as st
import pickle
import numpy as np
import matplotlib.pyplot as plt
import re
import nltk
from nltk.corpus import stopwords
from urllib.parse import urlparse
from io import BytesIO
import base64
import warnings

warnings.filterwarnings("ignore")

# Download stopwords if not already present
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

# Load vectorizer and model
with open('phishing_model.pkl', 'rb') as f:
    tf, model = pickle.load(f)

# Initialize stopwords
stop_words = set(stopwords.words('english'))


def create_safety_meter(value, color):
    """Create horizontal safety meter as base64 image"""
    fig, ax = plt.subplots(figsize=(5, 1))
    ax.barh([" "], [value], color=color, height=0.3)
    ax.set_xlim(0, 1)
    ax.axis('off')
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', transparent=True)
    plt.close(fig)
    return base64.b64encode(buf.getbuffer()).decode()


st.set_page_config(page_title="PhishGuard AI 🛡️", layout="wide")
st.markdown("<h1 style='text-align: center; color: #ff4b4b;'>PhishGuard AI 🕵️‍♂️</h1>",
            unsafe_allow_html=True)
st.markdown("<h4 style='text-align: center;'>Detect phishing emails with machine learning ⚔️</h4>",
            unsafe_allow_html=True)

email_text = st.text_area("📩 Paste the email content below:", height=200)

if st.button("🔍 Analyze Email"):
    if email_text.strip() == "":
        st.warning("Please enter email content to proceed.")
    else:
        # Transform input
        X_input = tf.transform([email_text])

        # Predict
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

        # Extract links and indicators
        links = re.findall(r'https?://\S+', email_text)
        indicators = {
            "Suspicious Links": len(links),
            "Urgency Keywords": sum(1 for _ in re.finditer(r"\burgent\b", email_text, re.IGNORECASE)),
            "Generic Greetings": any(word in email_text.lower() for word in ["dear user", "valued customer"]),
            "Misspelled Domains": sum(1 for link in links if any(c.isupper() for c in urlparse(link).netloc))
        }

        col1, col2 = st.columns(2)

        with col1:
            st.markdown(
                f"<h2 style='color: {color};'>{result}</h2>", unsafe_allow_html=True)
            st.progress(confidence)
            st.markdown(f"**Confidence:** `{confidence * 100:.2f}%`")

            # Feature Analysis
            st.markdown("### 🔑 Key Features")
            try:
                if hasattr(model, 'coef_'):
                    coefficients = model.coef_[0] if len(
                        model.coef_.shape) > 1 else model.coef_
                    features = tf.get_feature_names_out()
                    top_features = sorted(zip(features, coefficients),
                                          key=lambda x: abs(x[1]), reverse=True)[:10]

                    for word, score in top_features:
                        badge_color = "#ff4b4b" if score > 0 else "#4bb543"
                        st.markdown(f"""
                        <div style="padding: 8px; margin: 4px; border-radius: 5px;
                                    background: {badge_color}20; 
                                    border-left: 4px solid {badge_color};">
                            <span style="color: {badge_color}">●</span> **{word}** 
                            <span style="float: right;">{score:.4f}</span>
                        </div>
                        """, unsafe_allow_html=True)

                elif hasattr(model, 'feature_importances_'):
                    importances = model.feature_importances_
                    features = tf.get_feature_names_out()
                    top_features = sorted(zip(features, importances),
                                          key=lambda x: x[1], reverse=True)[:10]

                    for word, score in top_features:
                        st.markdown(f"""
                        <div style="padding: 8px; margin: 4px; border-radius: 5px;
                                    background: #e3f2fd; 
                                    border-left: 4px solid #2196f3;">
                            ▪ {word} <span style="float: right;">{score:.4f}</span>
                        </div>
                        """, unsafe_allow_html=True)

                else:
                    st.info("Feature analysis not available for this model type")

            except Exception as e:
                st.warning(f"Feature analysis failed: {str(e)}")

        with col2:
            # Combined Security Analysis Box
            safety_meter_img = create_safety_meter(safety_level, color)

            st.markdown(f"""
            <div style="padding: 25px; border-radius: 15px; border: 2px solid {color}; 
                        background: {color}08; margin-bottom: 20px;">
                <div style="margin-bottom: 20px;">
                    <h3 style="color: {color}; margin-top: 0;">🔒 Security Analysis</h3>
                    
                    <div style="margin-bottom: 25px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 16px;">🔗 Detected Links ({len(links)})</h4>
                        <div style="background: #f8f9fa; padding: 12px; border-radius: 8px;
                                    border: 1px solid #eee;">
                            {"<br>".join([f"• {urlparse(link).netloc}" for link in links]) if links else "No links found"}
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 25px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 16px;">🎮 Email Safety Meter</h4>
                        <img src="data:image/png;base64,{safety_meter_img}" style="width: 100%;">
                    </div>
                    
                    <div>
                        <h4 style="margin: 0 0 12px 0; font-size: 16px;">📊 Threat Breakdown</h4>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                            {''.join([
                f'''<div style="background: {'#ffebee' if value > 0 else '#f8f9fa'}; 
                                    padding: 12px; border-radius: 8px; border: 1px solid {'#ff4b4b33' if value > 0 else '#eee'};">
                                    {name}: <strong>{value if isinstance(value, bool) else value}</strong>
                                </div>'''
                for name, value in indicators.items()
            ])}
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.caption("Created with ❤️ by your AI Assistant. Stay safe online!")

# CSS Styling
st.markdown("""
<style>
div[data-testid="stExpander"] div[role="button"] p {
    font-size: 1.2rem;
    font-weight: bold;
}
div.stButton > button:first-child {
    width: 100%;
    border: 1px solid #ff4b4b;
    transition: all 0.2s;
}
div.stButton > button:first-child:hover {
    transform: scale(1.02);
    box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}
</style>
""", unsafe_allow_html=True)
