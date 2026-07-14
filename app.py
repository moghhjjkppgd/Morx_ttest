"""
مثال عملي بسيط: تسجيل الدخول عبر تيليجرام (Telegram Login Widget)
================================================================
هذا مشروع تجريبي صغير بس عشان تجرب كيف بيشتغل تسجيل الدخول عبر تيليجرام
على موقع ويب، قبل ما تقرر إذا بدك تستخدمه بموقع MORX الأساسي.

كيف يشتغل:
1. المستخدم يفتح الصفحة الرئيسية، بيشوف زر "Login with Telegram".
2. يدوس الزر، تيليجرام بتفتح نافذة تسأله "بتسمح لهذا الموقع يشوف اسمك؟"
3. بعد الموافقة، تيليجرام بترجعه لموقعك مع بياناته (id, اسمه, صورته) + توقيع أمني (hash).
4. السيرفر (هذا الملف) بيتحقق إنو التوقيع صحيح فعلاً من تيليجرام (مو مزوّر)،
   وبعدين بيعرض "أهلاً {الاسم}! الـID تبعك: {id}"

هذا الـID بالضبط هو نفس user_id يلي البوت يستخدمه لحفظ الرصيد --
يعني لو ربطنا هذا بقاعدة بيانات المحافظ (wallets_col)، العميل بيشوف
نفس رصيده بالضبط سواء دخل من البوت أو من الموقع.
"""

import os
import hashlib
import hmac
import time
from flask import Flask, request, render_template, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# نفس التوكن تبع بوت MORX (من متغيرات Railway)
BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
# اسم البوت بدون @ (مثال: MORXstore_bot)
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MORXstore_bot")


def verify_telegram_auth(auth_data: dict) -> bool:
    """يتحقق إن بيانات تسجيل الدخول فعلاً جاية من تيليجرام ومش مزوّرة"""
    if not BOT_TOKEN:
        return False
    data = auth_data.copy()
    received_hash = data.pop("hash", None)
    if not received_hash:
        return False

    # بناء نص التحقق: كل الحقول مرتبة أبجدياً بصيغة key=value مفصولة بسطر جديد
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))

    # المفتاح السري = SHA256 من توكن البوت
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    computed_hash = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()

    if computed_hash != received_hash:
        return False

    # تأكد إن البيانات مش قديمة (أكتر من يوم) لمنع إعادة استخدامها
    auth_date = int(data.get("auth_date", 0))
    if time.time() - auth_date > 86400:
        return False

    return True


@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user, bot_username=BOT_USERNAME)


@app.route("/auth")
def auth():
    """المسار يلي تيليجرام بترجّع له المستخدم بعد ما يوافق على تسجيل الدخول"""
    auth_data = request.args.to_dict()
    if not verify_telegram_auth(auth_data):
        return "❌ فشل التحقق من الهوية — البيانات مش موثوقة أو منتهية الصلاحية.", 403

    # نجح التحقق — نحفظ بيانات المستخدم بالجلسة (session)
    session["user"] = {
        "id": auth_data.get("id"),
        "first_name": auth_data.get("first_name", ""),
        "username": auth_data.get("username", ""),
        "photo_url": auth_data.get("photo_url", ""),
    }
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
