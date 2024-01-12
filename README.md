# Email Alert-Enabled Network Intrusion Detection Systems: A Supervised Machine Learning Approach with Recursive Feature Elimination

## Project Overview

This repository contains the source code and documentation for a Network Intrusion Detection System (NIDS) developed as a final year project. The system utilizes a supervised machine learning approach with Recursive Feature Elimination (RFE) for feature selection. The frontend is implemented using Flask, while the backend incorporates machine learning models for intrusion detection. Additionally, an email alert system is integrated to notify administrators of detected intrusions.

## Project Structure

### Directories

- `.vscode`: Configuration files for Visual Studio Code.
- `static`: Static files such as stylesheets, images, or JavaScript files.
- `templates`: HTML templates for the Flask application.
- `__pycache__`: Python bytecode cache (auto-generated, can be ignored).

### Files

- `app.py`: Main Flask application containing routes and backend logic.
- `database.db`: SQLite database for user authentication.
- `email_module.py`: Module for sending email alerts.
- `nids_single_model.pkl`: Pre-trained machine learning model for intrusion detection.
- `README.md`: Project documentation.

## Routes

### 1. Home Page

- **Route**: `/`
- **Functionality**: Displays the login form.
- **Method**: GET

### 2. Login

- **Route**: `/login`
- **Functionality**: Validates user credentials and redirects to the home page.
- **Method**: POST

... (other routes)

## Machine Learning Model (Pseudocode)

```python
# Import necessary libraries
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_selection import RFE
import matplotlib.pyplot as plt

# Load the dataset
data = pd.read_csv('/path/to/dataset.csv')

# ... (Code for data preprocessing)

# Train machine learning models (Decision Tree, Random Forest, SVM)
# ... (Code for model training)

# Feature selection using Recursive Feature Elimination (RFE)
rfe = RFE(estimator=dt_model, n_features_to_select=15)
X_train_rfe = rfe.fit_transform(X_train, y_train)

# Save the trained model
with open('NIDS_mapped_model.pkl', 'wb') as model_file:
    pickle.dump(rf_model, model_file)
```

### Backend (Flask Application)

The backend of the system is implemented using Flask, a Python web framework. The application includes routes and functionalities for managing the NIDS and triggering email alerts. It utilizes SQLite for database operations, pandas for data manipulation, pickle for serialization, and Werkzeug for password hashing.

```python
# Import necessary modules
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import pandas as pd
import pickle
from werkzeug.security import check_password_hash, generate_password_hash
import email_module

# ... (Code for Flask application setup)

# Define routes and functionalities
# ... (Code for route definitions)

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
```


The email alert system is implemented using Python and leverages the `smtplib` library for sending emails. The `send_email` function in `email_module.py` is responsible for composing and dispatching email alerts. This function takes parameters such as the result (e.g., "Attack Detected"), the type of attack, and the number of threads involved in the attack.

## Example Usage

```python
# Import the email_module
from email_module import send_email

# Trigger an email alert
send_email('Attack Detected', 'SQL Injection', 2)
```

## Getting Started

These instructions will help you set up and run the project on your local machine.

### Prerequisites

- Python 3.11.3
- [Virtual environment](https://docs.python.org/3/library/venv.html) (recommended)

### Installation

1. Clone the repository:
2. Navigate to the project directory
3. Create and activate a virtual environment (optional but recommended)
4. Install the project dependencies
   ```bash
   pip install -r requirements.txt
   ```
5. Running the Project
   ```bash
      python app.py
   ```
6. Open your web browser and go to http://localhost:5000/ to view the application.


