import numpy as np
import pandas as pd
import joblib
import ipaddress
from app.core.config import settings

# Load models and scalers once
attack_model = joblib.load(settings.ATTACK_MODEL_PATH)
attack_scaler = joblib.load(settings.ATTACK_SCALER_PATH)
severity_model = joblib.load(settings.SEVERITY_MODEL_PATH)
severity_scaler = joblib.load(settings.SEVERITY_SCALER_PATH)

rename_map = {
    "Source_IP_Address": "Source IP Address",
    "Destination_IP_Address": "Destination IP Address",
    "Malware_Indicators": "Malware Indicators",
    "Alerts_Warnings": "Alerts/Warnings",
    "Action_Taken": "Action Taken",
    "User_Information": "User Information",
    "Device_Information": "Device Information",
    "Network_Segment": "Network Segment",
    "Geo_location_Data": "Geo-location Data",
    "Proxy_Information": "Proxy Information",
    "Firewall_Logs": "Firewall Logs",
    "IDS_IPS_Alerts": "IDS/IPS Alerts",
    "Log_Source": "Log Source",
    "Packet_Type": "Packet Type",
    "Traffic_Type": "Traffic Type",
    "Payload_Data": "Payload Data",
    "Attack_Signature": "Attack Signature",
    "Severity_Level": "Severity Level",
    "Source_Port":"Source Port",
    "Destination_Port":"Destination Port",
    "Packet_Length":"Packet Length",
    "Anomaly_Scores":"Anomaly Scores"
}

attack_labels = {0: "DDoS", 1: "Intrusion", 2: "Malware"}
severity_labels = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}

def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except:
        return 0

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    df.rename(columns=rename_map, inplace=True)
    df['Source IP Address'] = df['Source IP Address'].apply(ip_to_int)
    df['Destination IP Address'] = df['Destination IP Address'].apply(ip_to_int)

    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df['Hour'] = df['Timestamp'].dt.hour.fillna(0).astype(int)
    df['Day of Week'] = df['Timestamp'].dt.weekday.fillna(0).astype(int)
    df.drop(['Timestamp', 'Proxy Information'], axis=1, inplace=True, errors='ignore')

    df['Malware Indicators'] = np.where(df['Malware Indicators'] == 'IoC Detected', 1, 0)
    df['Alerts/Warnings'] = np.where(df['Alerts/Warnings'] == 'Alert Triggered', 1, 0)

    for col in df.select_dtypes(include='object').columns:
        df[col] = df[col].astype('category').cat.codes

    return df

def predict_both(data: dict) -> dict:
    df = pd.DataFrame([data])
    df = preprocess(df)

    # Align features
    attack_X = df[attack_scaler.feature_names_in_]
    severity_X = df[severity_scaler.feature_names_in_]

    # Scale
    X_attack_scaled = attack_scaler.transform(attack_X)
    X_severity_scaled = severity_scaler.transform(severity_X)

    # Predict
    attack_pred = attack_model.predict(X_attack_scaled)[0]
    severity_pred = severity_model.predict(X_severity_scaled)[0]

    return {
        "attack_type": attack_labels.get(attack_pred, "Unknown"),
        "severity_level": severity_labels.get(severity_pred, "Unknown")
    }
