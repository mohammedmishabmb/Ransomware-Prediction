
from flask import Flask, request, render_template
from pathlib import Path
import pandas as pd
import joblib
import pefile

app = Flask(__name__)

# Allow only PE files for this prototype
ALLOWED_EXTENSIONS = {"exe", "dll"}

# Maximum upload size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 1000 * 1024 * 1024

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"

# Dataset feature order
FEATURE_COLUMNS = [
    "Machine",
    "DebugSize",
    "DebugRVA",
    "MajorImageVersion",
    "MajorOSVersion",
    "ExportRVA",
    "ExportSize",
    "IatVRA",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "NumberOfSections",
    "SizeOfStackReserve",
    "DllCharacteristics",
    "ResourceSize",
    "BitcoinAddresses",
]

# Load trained model
model = joblib.load(MODEL_PATH)


def allowed_file(filename):
    """Check whether the uploaded file has an allowed extension."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_directory_value(pe, directory_name, field_name):
    """Safely read a PE data-directory value."""
    try:
        directory_index = pefile.DIRECTORY_ENTRY[directory_name]
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
        return int(getattr(directory, field_name, 0))
    except Exception:
        return 0


def extract_features(file_bytes):
    """
    Extract static PE-header features.
    The file is parsed only; it is never executed.
    """

    pe = pefile.PE(data=file_bytes, fast_load=True)

    features = {
        "Machine": int(pe.FILE_HEADER.Machine),

        "DebugSize": get_directory_value(
            pe,
            "IMAGE_DIRECTORY_ENTRY_DEBUG",
            "Size",
        ),

        "DebugRVA": get_directory_value(
            pe,
            "IMAGE_DIRECTORY_ENTRY_DEBUG",
            "VirtualAddress",
        ),

        "MajorImageVersion": int(
            pe.OPTIONAL_HEADER.MajorImageVersion
        ),

        "MajorOSVersion": int(
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        ),

        "ExportRVA": get_directory_value(
            pe,
            "IMAGE_DIRECTORY_ENTRY_EXPORT",
            "VirtualAddress",
        ),

        "ExportSize": get_directory_value(
            pe,
            "IMAGE_DIRECTORY_ENTRY_EXPORT",
            "Size",
        ),

        "IatVRA": get_directory_value(
            pe,
            "IMAGE_DIRECTORY_ENTRY_IAT",
            "VirtualAddress",
        ),

        "MajorLinkerVersion": int(
            pe.OPTIONAL_HEADER.MajorLinkerVersion
        ),

        "MinorLinkerVersion": int(
            pe.OPTIONAL_HEADER.MinorLinkerVersion
        ),

        "NumberOfSections": int(
            pe.FILE_HEADER.NumberOfSections
        ),

        "SizeOfStackReserve": int(
            pe.OPTIONAL_HEADER.SizeOfStackReserve
        ),

        "DllCharacteristics": int(
            pe.OPTIONAL_HEADER.DllCharacteristics
        ),

        "ResourceSize": get_directory_value(
            pe,
            "IMAGE_DIRECTORY_ENTRY_RESOURCE",
            "Size",
        ),

        # This feature needs a more advanced string/resource scanner.
        # It is set to 0 for this initial prototype.
        "BitcoinAddresses": 0,
    }

    pe.close()
    return features


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return render_template(
            "index.html",
            error="Please select a file.",
        )

    if uploaded_file.filename == "":
        return render_template(
            "index.html",
            error="No file was selected.",
        )

    if not allowed_file(uploaded_file.filename):
        return render_template(
            "index.html",
            error="Only .exe and .dll files are supported.",
        )

    try:
        # Read the file into memory.
        # It is not executed.
        file_bytes = uploaded_file.read()

        features = extract_features(file_bytes)

        input_data = pd.DataFrame(
            [features],
            columns=FEATURE_COLUMNS,
        )

        prediction = int(model.predict(input_data)[0])

        if prediction == 0:
            result = "Potentially Malicious / Ransomware-like"
            result_class = "danger"
        else:
            result = "Likely Benign"
            result_class = "safe"

        confidence = None

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(input_data)[0]
            confidence = round(float(max(probabilities)) * 100, 2)

        return render_template(
            "index.html",
            filename=uploaded_file.filename,
            result=result,
            result_class=result_class,
            confidence=confidence,
            features=features,
        )

    except pefile.PEFormatError:
        return render_template(
            "index.html",
            error="This is not a valid Windows PE executable or DLL.",
        )

    except Exception as error:
        return render_template(
            "index.html",
            error=f"Analysis failed: {error}",
        )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )