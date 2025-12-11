# src/preprocess.py
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

def load_data(file_path):
    """Load data from a CSV file."""
    data = pd.read_csv(file_path)
    return data

def clean_data(data):
    """Clean the data by handling missing values and invalid data."""
    # Drop rows with any missing values
    data.dropna(inplace=True)

    # Drop duplicate rows
    data.drop_duplicates(inplace=True)

    # Remove packets with zero size (if applicable)
    data = data[data['pkt_size'] > 0]

    return data

def feature_engineering(data):
    """Create additional features for analysis."""
    # Extracting time features from timestamp
    data['timestamp'] = pd.to_datetime(data['timestamp'])
    data['hour'] = data['timestamp'].dt.hour
    data['day'] = data['timestamp'].dt.day
    data['month'] = data['timestamp'].dt.month

    # Create a flag for SYN packets, which are often part of DDoS attacks
    data['is_syn'] = data['flags'].apply(lambda x: 1 if x == 'S' else 0)

    return data

def normalize_data(data):
    """Normalize numerical features."""
    scaler = StandardScaler()
    data[['pkt_size']] = scaler.fit_transform(data[['pkt_size']])
    return data

def visualize_data(data):
    """Visualize the data to understand patterns."""
    plt.figure(figsize=(12, 6))
    sns.countplot(x='hour', data=data)
    plt.title('Packet Count by Hour')
    plt.xlabel('Hour of Day')
    plt.ylabel('Packet Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("../reports/packet_count_by_hour.png")
    plt.show()

    plt.figure(figsize=(12, 6))
    sns.histplot(data['pkt_size'], bins=50, kde=True)
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig("../reports/packet_size_distribution.png")
    plt.show()

def preprocess_data(file_path):
    """Main function to preprocess data."""
    # Load the data
    data = load_data(file_path)

    # Clean the data
    data = clean_data(data)

    # Feature Engineering
    data = feature_engineering(data)

    # Normalize Data
    data = normalize_data(data)

    # Save the processed data
    data.to_csv("../data/processed/processed_data.csv", index=False)

    # Visualize the data
    visualize_data(data)

if __name__ == "__main__":
    preprocess_data("../data/raw/captured_traffic.csv")
