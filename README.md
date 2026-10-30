# Ransomware Behavioral Detection Using Machine Learning

A machine-learning research prototype that classifies Windows PE files (EXE/DLL) as **likely benign** or **potentially malicious** using static Portable Executable (PE) features.

The project includes a Random Forest training pipeline, model evaluation outputs, and a Flask web interface for analyzing uploaded PE files without executing them.

## Features

- Loads a labelled CSV dataset and separates input features from the `Benign` target.
- Trains a `RandomForestClassifier`.
- Reports accuracy, classification metrics, and a confusion matrix.
- Exports feature-importance results and plots.
- Saves the trained model as a Joblib pickle.
- Provides a Flask interface that accepts `.exe` and `.dll` files.
- Extracts selected PE-header fields with `pefile` and passes them to the trained model.
- Displays the classification, model probability (when available), and extracted feature values.

## Project structure

```text
Ransomware-ML-Project/
├── dataset/
│   └── ransomware_data.csv
├── models/
├── results/
├── webapp/
│   ├── app.py
│   └── templates/
│       └── index.html
├── main.py
└── README.md
```

The `models/` and `results/` directories must exist before running the training script because the script writes output files into them.

## Technology stack

- Python
- pandas and scikit-learn
- Random Forest
- Joblib
- Matplotlib and Seaborn
- Flask
- pefile
- HTML/CSS

## Requirements

Use **Python 3.11 or 3.12** for the smoothest compatibility with the scientific Python packages. Other versions may work, but package compatibility can vary.

Required Python packages:

```text
pandas
scikit-learn
joblib
matplotlib
seaborn
flask
pefile
```

## Setup and run

The following steps assume you have cloned or downloaded this repository and opened the project root (`Ransomware-ML-Project`) in VS Code.

### 1. Install Python

Install Python 3.11 or 3.12 and ensure Python is available in your terminal.

Check:

```bash
python --version
```

### 2. Open the project folder

Open the `Ransomware-ML-Project` folder in VS Code.

Open the integrated terminal:

- Windows/Linux: `Ctrl + ``

Make sure the terminal is at the project root, where `main.py` is located.

### 3. Create a virtual environment

**Windows PowerShell:**

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

### 4. Install dependencies

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install the required packages:

```bash
python -m pip install pandas scikit-learn joblib matplotlib seaborn flask pefile
```

### 5. Check the dataset and output folders

Confirm that this file exists:

```text
dataset/ransomware_data.csv
```

Confirm that these folders exist:

```text
models/
results/
```

The dataset must contain the `Benign` target column and the feature columns expected by `main.py`. The script removes `FileName` and `md5Hash` from the input features.

### 6. Train the Random Forest model

From the project root, run:

```bash
python main.py
```

The script will:

1. Read `dataset/ransomware_data.csv`.
2. Split the data into training and testing sets (80% / 20%).
3. Train a Random Forest classifier with 100 trees.
4. Print accuracy, a classification report, and a confusion matrix.
5. Save the confusion-matrix image.
6. Save feature importance as a CSV and image.
7. Save the trained model to `models/random_forest_model.pkl`.

Expected output files:

```text
models/random_forest_model.pkl
results/confusion_matrix.png
results/feature_importance.csv
results/feature_importance.png
```

Your metrics may differ if the dataset or environment differs. Do not assume a particular accuracy before running the experiment.

### 7. Start the web application

Train the model first, or ensure that a compatible model file already exists at:

```text
models/random_forest_model.pkl
```

Start Flask from the **project root**:

```bash
python webapp/app.py
```

The application is configured to listen on:

```text
http://127.0.0.1:5000
```

Open that address in your browser.

### 8. Analyze a file

1. Use a benign test PE file from a trusted source or a purpose-built harmless test executable.
2. Select the `.exe` or `.dll` file in the web interface.
3. Click **Analyze File**.
4. Review the predicted class and extracted PE feature values.

The application parses the uploaded file as PE data; it does not intentionally execute the uploaded file. Nevertheless, file parsing is not risk-free. Test only in an isolated, patched environment and do not use live ransomware samples on your everyday computer.

## How it works

### Model training

`main.py` reads the dataset, removes the identifier columns `FileName` and `md5Hash`, and uses `Benign` as the target label. It performs a stratified train/test split and trains a Random Forest model.

### Web-based prediction

`webapp/app.py` accepts PE files, extracts a fixed list of static PE-header features with `pefile`, arranges them in the feature order expected by the model, and calls the saved model to predict a class.

The current web application sets `BitcoinAddresses` to `0` as a placeholder; it does not implement Bitcoin-address scanning. The application also uses the feature name `IatVRA`, matching the supplied project code.

## Current implementation scope and limitations

- The supplied training script trains **Random Forest**.
- The web application loads `random_forest_model.pkl`; it does not select between multiple models.
- The web application uses static PE-header features, not dynamic sandbox behavior monitoring.
- `BitcoinAddresses` is currently hard-coded to zero in the web feature extractor.
- The model is only as reliable as its dataset, labels, feature quality, and evaluation method.
- The displayed probability is the model's highest class probability; it should not automatically be interpreted as calibrated real-world confidence.
- The project does not implement automatic quarantine, deletion, process termination, or network isolation. It provides a prediction only.
- The saved Joblib model may require compatible versions of scikit-learn and its dependencies. If loading fails, recreate the virtual environment, install compatible packages, and retrain with `main.py`.

## Safety and responsible use

- Do not execute suspicious files to test this project.
- Do not use real ransomware on your host machine.
- Keep testing isolated from personal files and production networks.
- Do not expose the Flask development server directly to the internet.
- Do not treat a benign prediction as a guarantee of safety.
- Obtain authorization before analyzing files that do not belong to you.
- Review and comply with the dataset's license and usage terms before redistributing it.

## Troubleshooting

**`FileNotFoundError` for the CSV**

Run commands from the project root and check that `dataset/ransomware_data.csv` exists.

**`FileNotFoundError` for the model**

Run `python main.py` first and check that `models/random_forest_model.pkl` was created.

**`ModuleNotFoundError`**

Activate the virtual environment and install the packages listed in the requirements section.

**Invalid PE file**

The web application accepts Windows PE executables and DLLs. A renamed document, script, or other non-PE file will not work.

**Model loading or feature mismatch**

Use the same feature definitions and a compatible scikit-learn environment for training and inference. Retrain the model after changing the feature set.

