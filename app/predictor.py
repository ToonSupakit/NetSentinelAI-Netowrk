# นำเข้าไลบรารีที่จำเป็นสำหรับการทำนายด้วย AI
import joblib  # สำหรับโหลดและบันทึก AI model
import pandas as pd  # สำหรับจัดการข้อมูลแบบ DataFrame
import yaml  # สำหรับอ่านไฟล์การตั้งค่า
import logging
from app.db import save_prediction  # ฟังก์ชันสำหรับบันทึกผลการทำนาย

log = logging.getLogger(__name__)

# อ่านไฟล์การตั้งค่าจาก config.yaml
with open('config/config.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

# ตัวแปรโกลบอลสำหรับเก็บโมเดล
model = None

def reload_model():
    """โหลด หรือ โหลด AI model ใหม่จากไฟล์"""
    global model
    try:
        model = joblib.load(config['model']['path'])
        log.info(f"🔄 โหลด AI model สำเร็จจาก {config['model']['path']}")
    except FileNotFoundError:
        model = None
        log.warning(f"⚠️ ไม่พบ model file: {config['model']['path']} — ให้รัน train_model.py ก่อน")
    except Exception as e:
        model = None
        log.error(f"❌ โหลด model ล้มเหลว: {e}")

# โหลดครั้งแรกตอนเริ่มโปรแกรม
reload_model()

def analyze_cause(data):
    """วิเคราะห์สาเหตุและให้คำแนะนำสำหรับความผิดปกติ"""
    causes      = []  # รายการสาเหตุที่เป็นไปได้
    suggestions = []  # รายการคำแนะนำในการแก้ไข

    # ตรวจสอบ device down
    if data.get('is_device_down'):
        causes.append("อุปกรณ์เชื่อมต่อไม่ได้ (Device Unreachable)")
        suggestions.append("ตรวจสอบว่าอุปกรณ์เปิดอยู่และเครือข่ายถึงกัน")
        return causes, suggestions

    # ตรวจสอบสถานะ admin down
    if data['is_admin_down']:
        causes.append("Port ถูกปิดด้วยคำสั่ง shutdown")
        suggestions.append(f"no shutdown บน {data['intf']}")
    # ตรวจสอบสถานะ port up แต่ protocol down
    elif data['status_num'] == 1 and data['protocol_num'] == 0:
        causes.append("Port up แต่ Protocol down (Link down)")
        suggestions.append("ตรวจสอบสายและอุปกรณ์ปลายทาง")
    # ตรวจสอบสถานะ physical down
    elif data['status_num'] == 0:
        causes.append("Port ไม่ทำงาน (Physical down)")
        suggestions.append("ตรวจสอบสายและการเชื่อมต่อ")

    # ตรวจสอบ traffic ขาออกสูง
    if data['network_load'] > config['model']['threshold_load']:
        pct = round(data['network_load'] / 255 * 100, 1)
        causes.append(f"Traffic ขาออกสูง ({pct}%)")
        suggestions.append("ตรวจสอบ traffic อาจมี loop หรือ flood")

    # ตรวจสอบ traffic ขาเข้าสูง
    if data['rxload'] > config['model']['threshold_load']:
        pct = round(data['rxload'] / 255 * 100, 1)
        causes.append(f"Traffic ขาเข้าสูง ({pct}%)")
        suggestions.append("ตรวจสอบ traffic อาจถูก DDoS")

    # ตรวจสอบความเสถียรต่ำ
    if data['reliability'] < config['model']['threshold_reliability']:
        pct = round(data['reliability'] / 255 * 100, 1)
        causes.append(f"ความเสถียรต่ำ ({pct}%)")
        suggestions.append("ตรวจสอบคุณภาพสาย")

    # ตรวจสอบ input errors สูง
    if data['input_errors'] > config['model']['threshold_errors']:
        causes.append(f"Input errors {data['input_errors']} ครั้ง")
        suggestions.append("ตรวจสอบ duplex mismatch หรือสายชำรุด")

    # ถ้าไม่มีกฎไหนตรงเลย แต่ยังถูกส่งมา แปลว่า AI ตรวจเจอพฤติกรรมผิดปกติ
    if not causes:
        causes.append("AI ตรวจพบพฤติกรรมผิดปกติ (Unusual Pattern Detection)")
        suggestions.append("ตรวจสอบกราฟ Traffic อาจมีแพทเทิร์นที่ต่างไปจากเดิม")

    return causes, suggestions

def predict_one(data):
    """ทำนายความผิดปกติสำหรับข้อมูล interface ชุดเดียว

    AI ทำงานคู่ขนานกับ Rules เสมอ (ไม่ใช่แค่ด่านสอง):
    1) device_unreachable — เก็บข้อมูลไม่ได้
    2) rules+ai — ทั้ง Rules และ AI เห็นตรงกันว่าผิดปกติ
    3) rules — เฉพาะ Rules บอกว่าผิดปกติ (AI ไม่พบ หรือไม่มี model)
    4) ai — เฉพาะ AI ตรวจพบ pattern ผิดปกติ (Rules มองว่าปกติ)
    5) healthy — ผ่านทั้ง Rules และ AI
    """
    if data.get('is_device_down'):
        return 'anomaly', 1.0, 'device_unreachable'

    rules_says_anomaly = (data['label'] == 'anomaly')

    # ── AI Analysis (ทำงานเสมอถ้ามี model) ──────────────────────────────
    ai_says_anomaly = False
    ai_confidence = 0.0

    if model is not None:
        features = pd.DataFrame([{
            'reliability'  : data['reliability'],
            'network_load' : data['network_load'],
            'rxload'       : data['rxload'],
            'input_errors' : data['input_errors']
        }])

        pred_int = model.predict(features)[0]
        # decision_function: ค่ายิ่งติดลบ = ยิ่ง outlier
        score = model.decision_function(features)[0]
        ai_confidence = min(1.0, max(0.0, 0.5 - score))  # แปลงเป็น 0-1

        if pred_int == -1:
            ai_says_anomaly = True

    # ── ตัดสินผลรวม ─────────────────────────────────────────────────────
    if rules_says_anomaly and ai_says_anomaly:
        # ทั้งสองเห็นตรงกัน → ความมั่นใจสูงสุด
        return 'anomaly', max(0.95, ai_confidence), 'rules+ai'

    if rules_says_anomaly:
        # เฉพาะ Rules เห็น (AI อาจไม่มี model หรือ AI ไม่เห็นด้วย)
        return 'anomaly', 1.0, 'rules'

    if ai_says_anomaly:
        # เฉพาะ AI เห็น — pattern ผิดปกติที่ Rules ไม่ครอบคลุม
        return 'anomaly', round(ai_confidence, 4), 'ai'

    # ผ่านทั้งคู่
    return 'normal', 1.0, 'healthy'

def predict_all(collected_data):
    """ทำนายความผิดปกติสำหรับข้อมูล interface ทั้งหมด"""
    anomalies = []  # รายการความผิดปกติที่พบ

    # วนลูปทำนายทีละ interface
    for data in collected_data:
        prediction, confidence, detection_source = predict_one(data)

        save_prediction(
            data['log_id'],
            data['device'],
            data['intf'],
            prediction,
            round(confidence, 4),
            detection_source=detection_source,
        )

        if prediction == 'anomaly':
            causes, suggestions = analyze_cause(data)
            anomalies.append({
                **data,
                'prediction'        : prediction,
                'confidence'        : confidence,
                'detection_source'  : detection_source,
                'causes'            : causes,
                'suggestions'       : suggestions,
            })
            log.info(
                "Anomaly %s %s source=%s confidence=%.2f",
                data['device'],
                data['intf'],
                detection_source,
                confidence,
            )

    return anomalies