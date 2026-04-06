import joblib
import numpy as np
import pandas as pd
import os

MODEL_DIR = os.path.join(os.path.dirname(__file__), '../models')

def predict_new_connection(new_row_df):
    """Loads artifacts, processes a new network connection, and returns a prediction."""
    
    loaded_rf = joblib.load(os.path.join(MODEL_DIR, 'random_forest_nids.pkl'))
    loaded_scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
    loaded_features = joblib.load(os.path.join(MODEL_DIR, 'selected_features.pkl'))

    num_cols = new_row_df.select_dtypes(include=[np.number]).columns.drop('labels', errors='ignore')
    new_row_scaled_full = loaded_scaler.transform(new_row_df[num_cols])

    feature_indices = [list(num_cols).index(f) for f in loaded_features]
    new_row_selected = new_row_scaled_full[:, feature_indices]

    prediction = loaded_rf.predict(new_row_selected)
    return "ATTACK (1)" if prediction == 1 else "BENIGN (0)"
