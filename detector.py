
import pandas as pd
from sklearn.ensemble import IsolationForest

PROTOCOL_CODES = {
    "OTHER": 0,
    "ICMP": 1,
    "TCP": 2,
    "UDP": 3,
    "DNS": 4,
}

def detect_anomalies(df):
    result = df.copy()
    result["status"] = "Collecting baseline"
    result["anomaly_score"] = 0.0

    if len(result) < 50:
        return result

    features = pd.DataFrame({
        "packet_size": result["packet_size"],
        "destination_port": result["destination_port"],
        "protocol_code": result["protocol"].map(
            PROTOCOL_CODES
        ).fillna(0),
        "interarrival_seconds": result[
            "interarrival_seconds"
        ],
    }).fillna(0)

    baseline = features.iloc[:50]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(baseline)

    prediction = model.predict(features)
    scores = -model.decision_function(features)

    result["status"] = [
        "Anomaly" if p == -1 else "Normal"
        for p in prediction
    ]
    result["anomaly_score"] = scores
    result.iloc[:50, result.columns.get_loc("status")] = (
        "Baseline"
    )

    return result
