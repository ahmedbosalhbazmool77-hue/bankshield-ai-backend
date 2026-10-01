from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import re

app = FastAPI(
    title="BankShield AI",
    description="نظام ذكي للكشف المبكر عن الروابط المشبوهة",
    version="1.0.0"
)


class URLRequest(BaseModel):
    url: str


def analyze_url(url: str):
    reasons = []
    score = 0

    # إضافة البروتوكول إذا لم يكن موجودًا
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    full_url = url.lower()

    # طول الرابط
    if len(url) > 100:
        score += 15
        reasons.append("الرابط طويل بشكل غير معتاد")

    # استخدام عنوان IP بدل اسم النطاق
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
        score += 30
        reasons.append("الرابط يستخدم عنوان IP بدل اسم نطاق")

    # كلمات شائعة في روابط التصيد
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "bank",
        "wallet",
        "signin"
    ]

    found_keywords = [
        word for word in suspicious_keywords
        if word in full_url
    ]

    if found_keywords:
        score += min(len(found_keywords) * 8, 30)
        reasons.append(
            "وجود كلمات مرتبطة بتسجيل الدخول أو التحقق: "
            + ", ".join(found_keywords)
        )

    # كثرة النطاقات الفرعية
    subdomains = hostname.count(".")

    if subdomains >= 3:
        score += 15
        reasons.append("عدد النطاقات الفرعية مرتفع")

    # وجود @ في الرابط
    if "@" in url:
        score += 20
        reasons.append("الرابط يحتوي على الرمز @ بطريقة مشبوهة")

    # استخدام HTTP
    if parsed.scheme == "http":
        score += 10
        reasons.append("الرابط لا يستخدم HTTPS")

    # وجود ترميز URL
    if "%" in url:
        score += 10
        reasons.append("الرابط يحتوي على ترميز URL")

    # الحد الأقصى للدرجة
    score = min(score, 100)

    # التصنيف
    if score < 30:
        classification = "LOW"
    elif score < 60:
        classification = "MEDIUM"
    elif score < 80:
        classification = "HIGH"
    else:
        classification = "CRITICAL"

    return {
        "url": url,
        "risk_score": score,
        "classification": classification,
        "reasons": reasons
    }


@app.get("/")
def home():
    return {
        "system": "BankShield AI",
        "status": "running"
    }


@app.post("/scan-url")
def scan_url(request: URLRequest):
    return analyze_url(request.url)
class MessageRequest(BaseModel):
    message: str


@app.post("/scan-message")
def scan_message(data: MessageRequest):
    message = data.message.lower()

    suspicious_words = [
        "verify", "login", "account", "password", "bank",
        "urgent", "update", "blocked", "suspended",
        "تحقق", "تسجيل الدخول", "حساب", "كلمة المرور",
        "البنك", "عاجل", "تحديث", "معلق", "موقوف"
    ]

    found = [word for word in suspicious_words if word in message]

    risk_score = min(len(found) * 15, 100)

    if risk_score >= 80:
        classification = "CRITICAL"
    elif risk_score >= 60:
        classification = "HIGH"
    elif risk_score >= 30:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    reasons = []

    if found:
        reasons.append(
            "تم العثور على كلمات مرتبطة بالتصيد أو الهندسة الاجتماعية"
        )

    if "http://" in message or "https://" in message:
        reasons.append("الرسالة تحتوي على رابط")

    if any(word in message for word in ["عاجل", "urgent", "فوراً"]):
        reasons.append("استخدام أسلوب الاستعجال والضغط على المستخدم")

    return {
        "message": data.message,
        "risk_score": risk_score,
        "classification": classification,
        "reasons": reasons,
        "detected_indicators": found
    }
    