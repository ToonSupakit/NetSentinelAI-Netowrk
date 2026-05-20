# Import required libraries for AI prediction
import joblib  # For loading and saving AI models
import yaml  # For reading configuration files
import logging
from app import prediction_intel
from app.ai_features import frame_for_prediction
from app.db import (
    get_interface_runtime_features,
    save_prediction,
)  # Function for saving prediction results

log = logging.getLogger(__name__)

# Read configuration settings from config.yaml
with open("config/config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

# Global variable for holding the loaded model
model = None


def reload_model():
    """Load or reload the AI model from the configured path."""
    global model
    try:
        model = joblib.load(config["model"]["path"])
        log.info(f"🔄 Loaded AI model successfully from {config['model']['path']}")
    except FileNotFoundError:
        model = None
        log.warning(
            f"⚠️ Model file not found: {config['model']['path']} — run train_model.py first"
        )
    except Exception as e:
        model = None
        log.error(f"❌ Failed to load model: {e}")


# Load the model upon program initialization
reload_model()


def analyze_cause(data):
    return prediction_intel.analyze_cause(data, config)


def predict_one(data):
    """Predict anomalies for a single interface dataset.

    AI runs in parallel with heuristic Rules:
    1) device_unreachable - Device cannot be collected
    2) rules+ai - Both rules and AI classify as anomaly
    3) rules - Classified as anomaly by rules only (AI says normal, or model missing)
    4) ai - Classified as anomaly by AI only (rules say healthy)
    5) healthy - Classified as healthy by both rules and AI
    """
    if data.get("is_device_down"):
        return "anomaly", 1.0, "device_unreachable"

    rules_says_anomaly = data["label"] == "anomaly"

    # -- AI Analysis (runs if the model is loaded) ----------------------------
    ai_says_anomaly = False
    ai_confidence = 0.0

    if model is not None:
        features = frame_for_prediction(data, model)

        pred_int = model.predict(features)[0]
        # decision_function: more negative value = more outlier
        score = model.decision_function(features)[0]
        ai_confidence = min(1.0, max(0.0, 0.5 - score))  # map score to 0-1 confidence

        if pred_int == -1:
            ai_says_anomaly = True

    # -- Combined Decision ----------------------------------------------------
    if rules_says_anomaly and ai_says_anomaly:
        # Both methods agree -> highest confidence
        return "anomaly", max(0.95, ai_confidence), "rules+ai"

    if rules_says_anomaly:
        # Rules only (AI says normal or model missing)
        return "anomaly", 1.0, "rules"

    if ai_says_anomaly:
        # AI only -> unusual pattern that rules did not cover
        return "anomaly", round(ai_confidence, 4), "ai"

    # Both agree it is normal
    return "normal", 1.0, "healthy"


def enrich_runtime_features(data):
    enriched = dict(data)
    if data.get("is_device_down") or data.get("intf") == "ALL":
        return enriched
    try:
        features = get_interface_runtime_features(
            data.get("device"),
            data.get("intf"),
            current_log_id=data.get("log_id"),
            window=config.get("model", {}).get("feature_window", 20),
        )
        enriched.update(features)
    except Exception as e:
        log.debug("Runtime feature enrichment failed for %s/%s: %s", data.get("device"), data.get("intf"), e)
    return enriched


def classify_severity(data, confidence, detection_source):
    return prediction_intel.classify_severity(data, confidence, detection_source, config)


def _is_down_event(anomaly):
    return prediction_intel.is_down_event(anomaly)


def _is_root_event(anomaly):
    return prediction_intel.is_root_event(anomaly)


def _same_area(root, child):
    return prediction_intel.same_area(root, child)


def apply_correlation(anomalies):
    return prediction_intel.apply_correlation(anomalies)


def predict_all(collected_data):
    """Predict anomalies for all collected interface data."""
    records = []
    anomalies = []

    for raw in collected_data:
        data = enrich_runtime_features(raw)
        prediction, confidence, detection_source = predict_one(data)
        record = {
            "data": data,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "detection_source": detection_source,
            "severity": None,
            "correlated_with": None,
            "notification_suppressed": False,
        }
        records.append(record)

        if prediction == "anomaly":
            causes, suggestions = analyze_cause(data)
            severity = classify_severity(data, confidence, detection_source)
            anomaly = {
                **data,
                "prediction": prediction,
                "confidence": confidence,
                "detection_source": detection_source,
                "severity": severity,
                "correlated_with": None,
                "notification_suppressed": False,
                "causes": causes,
                "suggestions": suggestions,
            }
            record["severity"] = severity
            record["anomaly_ref"] = anomaly
            anomalies.append(anomaly)

    apply_correlation(anomalies)
    for record in records:
        anomaly = record.get("anomaly_ref")
        if anomaly:
            record["correlated_with"] = anomaly.get("correlated_with")
            record["notification_suppressed"] = anomaly.get("notification_suppressed", False)

        data = record["data"]
        save_prediction(
            data["log_id"],
            data["device"],
            data["intf"],
            record["prediction"],
            record["confidence"],
            detection_source=record["detection_source"],
            severity=record["severity"],
            correlated_with=record["correlated_with"],
            notification_suppressed=record["notification_suppressed"],
        )

        if record["prediction"] == "anomaly":
            log.info(
                "Anomaly %s %s source=%s severity=%s confidence=%.2f suppressed=%s",
                data["device"],
                data["intf"],
                record["detection_source"],
                record["severity"],
                record["confidence"],
                record["notification_suppressed"],
            )

    return [a for a in anomalies if not a.get("notification_suppressed")]
