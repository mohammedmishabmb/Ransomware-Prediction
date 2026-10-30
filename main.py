
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==========================================
# 1. LOAD DATASET
# ==========================================

df = pd.read_csv("dataset/ransomware_data.csv")

print("Dataset loaded successfully!")
print("Total samples:", len(df))

# ==========================================
# 2. PREPARE FEATURES AND TARGET
# ==========================================

X = df.drop(columns=["FileName", "md5Hash", "Benign"])
y = df["Benign"]

print("\nNumber of features:", X.shape[1])

print("\nTarget distribution:")
print(y.value_counts())

# ==========================================
# 3. SPLIT DATASET
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

print("\nDataset split completed successfully!")

# ==========================================
# 4. TRAIN RANDOM FOREST MODEL
# ==========================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

print("\nTraining Random Forest model...")

model.fit(X_train, y_train)

print("Random Forest training completed!")

# ==========================================
# 5. PREDICTIONS AND EVALUATION
# ==========================================

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:", accuracy * 100, "%")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix:")
print(cm)

# ==========================================
# 6. CONFUSION MATRIX GRAPH
# ==========================================

plt.figure(figsize=(7, 5))

sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Malicious (0)", "Benign (1)"],
    yticklabels=["Malicious (0)", "Benign (1)"]
)

plt.title("Random Forest Confusion Matrix")
plt.xlabel("Predicted Label")
plt.ylabel("Actual Label")

plt.tight_layout()

plt.savefig(
    "results/confusion_matrix.png",
    dpi=300
)

plt.show()

# ==========================================
# 7. FEATURE IMPORTANCE
# ==========================================

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nFeature Importance:")
print(feature_importance)

feature_importance.to_csv(
    "results/feature_importance.csv",
    index=False
)

plt.figure(figsize=(10, 6))

plt.barh(
    feature_importance["Feature"],
    feature_importance["Importance"]
)

plt.xlabel("Importance")
plt.ylabel("PE File Feature")
plt.title("Random Forest Feature Importance")

plt.gca().invert_yaxis()

plt.tight_layout()

plt.savefig(
    "results/feature_importance.png",
    dpi=300
)

plt.show()

# ==========================================
# 8. SAVE TRAINED MODEL
# ==========================================

joblib.dump(
    model,
    "models/random_forest_model.pkl"
)

print("\nRandom Forest model saved successfully!")