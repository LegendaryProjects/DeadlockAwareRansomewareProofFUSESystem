import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Import your actual feature extraction logic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../feature_extraction')))
from entropy_calc import calculate_shannon_entropy, calculate_chi_square

# Directory configurations
BASE_DIR = os.path.dirname(__file__)
DATASETS_DIR = os.path.abspath(os.path.join(BASE_DIR, '../datasets'))
SAVE_DIR = os.path.abspath(os.path.join(BASE_DIR, '../saved_models'))
os.makedirs(SAVE_DIR, exist_ok=True)

# Define the block size to match the C++ FUSE interception buffer
CHUNK_SIZE = 65536 

def extract_features_from_directory(directory_path, label):
    """
    Reads files from a directory, extracts the first 64KB chunk (to simulate 
    FUSE interception), calculates features, and assigns the label.
    """
    X = []
    y = []
    
    if not os.path.exists(directory_path):
        print(f"[WARNING] Directory not found: {directory_path}. Skipping.")
        return X, y

    print(f"[*] Processing files in {directory_path} (Label: {label})...")
    
    for filename in os.listdir(directory_path):
        filepath = os.path.join(directory_path, filename)
        
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    # Read only the first 64KB to mimic the kernel IRP_MJ_WRITE intercept
                    data_buffer = f.read(CHUNK_SIZE)
                    
                    if len(data_buffer) < 512:
                        continue # Skip incredibly small files that skew entropy
                    
                    entropy = calculate_shannon_entropy(data_buffer)
                    chi_square = calculate_chi_square(data_buffer)
                    
                    X.append([entropy, chi_square])
                    y.append(label)
            except Exception as e:
                # Handle permission errors or corrupted files gracefully
                pass 
                
    return X, y

def train_model():
    X = []
    y = []
    
    # 1. Load Benign and Compressed Data (Label 0: Safe)
    benign_dir = os.path.join(DATASETS_DIR, 'benign')
    X_benign, y_benign = extract_features_from_directory(benign_dir, 0)
    
    compressed_dir = os.path.join(DATASETS_DIR, 'compressed')
    X_comp, y_comp = extract_features_from_directory(compressed_dir, 0)
    
    # 2. Load Malicious Ransomware Data (Label 1: Malicious)
    malicious_dir = os.path.join(DATASETS_DIR, 'malicious')
    X_mal, y_mal = extract_features_from_directory(malicious_dir, 1)
    
    # Combine all extracted features
    X.extend(X_benign + X_comp + X_mal)
    y.extend(y_benign + y_comp + y_mal)
    
    if not X:
        print("[ERROR] No data found! Please populate the datasets/ folders.")
        sys.exit(1)
        
    X = np.array(X)
    y = np.array(y)

    print(f"\n[*] Total samples extracted: {len(X)}")
    print("[*] Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[*] Training Random Forest Classifier...")
    # 100 decision trees is the optimal balance for accuracy vs. inference speed
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf_model.fit(X_train, y_train)

    print("[*] Evaluating Model on Test Set...")
    predictions = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Real-Data Model Accuracy: {accuracy * 100:.2f}%\n")
    print(classification_report(y_test, predictions, target_names=["Benign (0)", "Malicious (1)"]))

    model_path = os.path.join(SAVE_DIR, 'rf_ransomware_model.pkl')
    joblib.dump(rf_model, model_path)
    print(f"[*] Production Model successfully saved to {model_path}")

if __name__ == "__main__":
    train_model()