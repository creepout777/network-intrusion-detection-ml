"""
NSL-KDD Dataset Preprocessing Module

This module handles data loading, cleaning, encoding, scaling, and feature engineering
for the NSL-KDD intrusion detection dataset.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os

# NSL-KDD feature names (41 features + 1 label + 1 difficulty)
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERICAL_FEATURES = [col for col in FEATURE_NAMES if col not in CATEGORICAL_FEATURES and col not in ['label', 'difficulty']]


def load_dataset(train_path, test_path):
    """
    Load NSL-KDD train and test datasets.
    
    Args:
        train_path: Path to KDDTrain+.txt
        test_path: Path to KDDTest+.txt
    
    Returns:
        tuple: (train_df, test_df)
    """
    print("Loading NSL-KDD dataset...")
    train_df = pd.read_csv(train_path, header=None, names=FEATURE_NAMES)
    test_df = pd.read_csv(test_path, header=None, names=FEATURE_NAMES)
    
    # Strip stray whitespace from the text columns
    for df in (train_df, test_df):
        for col in df.select_dtypes(include="object").columns:
            df[col] = df[col].str.strip()
    
    print(f"✓ Train set shape: {train_df.shape}")
    print(f"✓ Test set shape: {test_df.shape}")
    
    return train_df, test_df


def analyze_dataset(df, name="Dataset"):
    """Display dataset analysis."""
    print(f"\n{name} Analysis:")
    print(f"  Shape: {df.shape}")
    print(f"  Missing values: {df.isnull().sum().sum()}")
    print(f"  Attack types: {df['label'].value_counts().to_dict()}")
    print(f"  Data types:\n{df.dtypes}")


def preprocess_data(train_df, test_df, output_dir="data/processed"):
    """
    Preprocess training and test datasets.
    
    Args:
        train_df: Training dataframe
        test_df: Test dataframe
        output_dir: Directory to save processed data
    
    Returns:
        dict: Contains X_train, X_test, y_train, y_test, encoders, scaler
    """
    print("\n" + "="*60)
    print("DATA PREPROCESSING")
    print("="*60)
    
    # Analyze original data
    analyze_dataset(train_df, "Training Set")
    analyze_dataset(test_df, "Test Set")
    
    # Convert attack labels to binary (Normal vs Attack)
    print("\nConverting labels to binary classification...")
    train_df['label_binary'] = (train_df['label'] != 'normal').astype(int)
    test_df['label_binary'] = (test_df['label'] != 'normal').astype(int)
    
    print(f"  Normal: {(train_df['label_binary'] == 0).sum()}")
    print(f"  Attack: {(train_df['label_binary'] == 1).sum()}")
    
    # Convert duration from string to numeric
    print("Converting duration column to numeric...")
    train_df['duration'] = pd.to_numeric(train_df['duration'], errors='coerce')
    test_df['duration'] = pd.to_numeric(test_df['duration'], errors='coerce')
    print(f"  ✓ Duration converted")
    
    # Initialize encoders
    label_encoders = {}
    
    # Encode categorical features
    print("\nEncoding categorical features...")
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        # Fit on combined train and test data to handle all unique values
        combined_values = pd.concat([train_df[col], test_df[col]]).unique()
        le.fit(combined_values)
        train_df[col] = le.transform(train_df[col])
        test_df[col] = le.transform(test_df[col])
        label_encoders[col] = le
        print(f"  ✓ {col}: {len(le.classes_)} unique values")
    
    # Prepare feature and target sets
    X_train = train_df.drop(['label', 'label_binary', 'difficulty'], axis=1)
    X_test = test_df.drop(['label', 'label_binary', 'difficulty'], axis=1)
    y_train = train_df['label_binary']
    y_test = test_df['label_binary']
    
    # Scale numerical features
    print("\nScaling numerical features...")
    scaler = StandardScaler()
    X_train[NUMERICAL_FEATURES] = scaler.fit_transform(X_train[NUMERICAL_FEATURES])
    X_test[NUMERICAL_FEATURES] = scaler.transform(X_test[NUMERICAL_FEATURES])
    print(f"  ✓ Scaled {len(NUMERICAL_FEATURES)} numerical features")
    
    # Handle any remaining NaN/inf values
    X_train = X_train.replace([np.inf, -np.inf], np.nan).fillna(0)
    X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    # Save processed data
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nSaving processed data to {output_dir}...")
    X_train.to_csv(f"{output_dir}/X_train.csv", index=False)
    X_test.to_csv(f"{output_dir}/X_test.csv", index=False)
    y_train.to_csv(f"{output_dir}/y_train.csv", index=False)
    y_test.to_csv(f"{output_dir}/y_test.csv", index=False)
    
    joblib.dump(scaler, f"{output_dir}/scaler.pkl")
    joblib.dump(label_encoders, f"{output_dir}/label_encoders.pkl")
    
    print("✓ Preprocessed data saved successfully")
    
    return {
        'X_train': X_train,
        'X_test': X_test,
        'y_train': y_train,
        'y_test': y_test,
        'scaler': scaler,
        'label_encoders': label_encoders
    }


if __name__ == "__main__":
    # Run from the repository root: python src/training/preprocess.py
    train_df, test_df = load_dataset("data/raw/KDDTrain+.txt", "data/raw/KDDTest+.txt")
    data = preprocess_data(train_df, test_df)
    
    print("\n" + "="*60)
    print("PREPROCESSING COMPLETE")
    print("="*60)
    print(f"Final shapes:")
    print(f"  X_train: {data['X_train'].shape}")
    print(f"  X_test: {data['X_test'].shape}")
    print(f"  y_train: {data['y_train'].shape}")
    print(f"  y_test: {data['y_test'].shape}")
