# Phishing Email Detection with Deep Learning

## Project Overview

This project implements a phishing email detection system using deep learning techniques. It uses a Bidirectional GRU (Gated Recurrent Unit) model to classify emails or messages as either phishing attempts or safe communications. The model achieves approximately 96% accuracy on the test dataset.

The system includes:
- A Streamlit web application for interactive phishing detection.
- Preprocessing and prediction utilities.
- A training notebook demonstrating data preparation, model building, training, and evaluation.

## Installation

These instructions will help you set up the project on your local machine. The steps are designed to be beginner-friendly.

### Prerequisites

- Python 3.7 or higher installed. You can download it from [python.org](https://www.python.org/downloads/).
- pip package manager (usually comes with Python).
- (Optional but recommended) Virtual environment tool such as `venv` or `virtualenv`.

### Setup Steps

1. **Clone or download the project files** to your local machine.

2. **Open a terminal or command prompt** and navigate to the project directory.

3. **Create a virtual environment** (recommended to avoid dependency conflicts):

   On Windows:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```

   On macOS/Linux:
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Upgrade pip** (optional but recommended):
   ```
   pip install --upgrade pip
   ```

5. **Install the required dependencies**:
   ```
   pip install -r requirements.txt
   ```

6. **Run the Streamlit app**:
   ```
   streamlit run app.py
   ```

7. **Open the URL** shown in the terminal (usually http://localhost:8501) in your web browser to use the app.

## Usage

The Streamlit app provides the following features:

- **Single Prediction**: Enter an email or message text to predict if it is phishing or safe.
- **Batch Prediction**: Upload a CSV file containing emails/messages to analyze in batch.
- **Model Evaluation**: View performance metrics such as accuracy, precision, recall, and confusion matrix.
- **About**: Learn about the model architecture, training data, and performance.

## Model Architecture and Performance

- Embedding layer with vocabulary size 10,000 and embedding dimension 64.
- Bidirectional GRU layer with 64 units.
- Dropout layer with rate 0.5.
- Dense layer with 32 units and ReLU activation.
- Output layer with sigmoid activation for binary classification.

Performance on test data:
- Accuracy: 96%
- Precision: 97%
- Recall: 95%

## Training Details

Training is demonstrated in the `notebook/training.ipynb` Jupyter notebook, which covers:

- Data loading and preprocessing (cleaning, stopword removal, stemming).
- Text vectorization using Keras Tokenizer and padding.
- Train-test split with stratification.
- Model building, compilation, and training with early stopping.
- Evaluation with classification report and confusion matrix.
- Saving the trained model and preprocessing artifacts (`phishing_gru_model.h5`, `tokenizer.pkl`, `label_encoder.pkl`).

## File Descriptions

- `app.py`: Main Streamlit application for phishing detection.
- `notebook/training.ipynb`: Jupyter notebook for training and evaluating the model.
- `phishing_gru_model.h5`: Trained Keras model file.
- `tokenizer.pkl`: Tokenizer object for text vectorization.
- `label_encoder.pkl`: Label encoder for converting labels.
- CSV files: Sample datasets and prediction outputs.

## Future Improvements

- Experiment with advanced embeddings like GloVe or BERT.
- Explore hybrid CNN-LSTM architectures.
- Incorporate additional features such as URL analysis and email header inspection.
- Collect more diverse phishing examples for training.

## Deployment Ideas

- Integrate as an email server plugin to filter incoming messages.
- Develop a browser extension to warn users about suspicious content.
- Provide an API service for applications to check messages programmatically.

## License

This project is provided as-is for educational and research purposes.
## Connect with Shakefire to explore more...!!!

Thank you for using this phishing email detection system! 
