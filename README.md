# هینا هوم — نسخه Netlify + PostgreSQL

این نسخه برای انتشار روی Netlify آماده شده است. رابط سایت در `public/` منتشر می‌شود و API از طریق Netlify Functions اجرا می‌شود. حساب‌ها، نشست‌ها، محصولات و سفارش‌ها به PostgreSQL خارجی نیاز دارند.

## مراحل انتشار

1. این پوشه را در یک مخزن GitHub آپلود کنید (محتویات همین پوشه در ریشه مخزن باشند).
2. یک PostgreSQL مدیریت‌شده در سرویس دیتابیس مثل Neon یا Supabase بسازید و connection string را بردارید. دیتابیس باید از Netlify Functions قابل دسترسی باشد و TLS/SSL فعال باشد.
3. در Netlify، گزینه Add new site / Import an existing project را انتخاب و مخزن GitHub را وصل کنید. تنظیمات build از `netlify.toml` خوانده می‌شوند.
4. در Netlify → Site configuration → Environment variables این متغیرها را اضافه کنید: `NODE_ENV=production`, `DATABASE_URL` (connection string دیتابیس), `SESSION_SECRET` (رشته تصادفی حداقل ۳۲ کاراکتری), `ADMIN_EMAIL` (ایمیل مدیر), `ADMIN_PASSWORD_HASH` (هش bcrypt رمز مدیریت). این مقادیر را در Git یا فایل‌های عمومی قرار ندهید.
5. برای تولید هش رمز ادمین، بعد از `npm install` روی کامپیوتر مورد اعتماد، متغیر `ADMIN_PASSWORD` را موقتاً در ترمینال قرار دهید و اجرا کنید:
   `node -e "const c=require('crypto'),b=require('bcrypt'); b.hash(c.createHash('sha256').update(process.env.ADMIN_PASSWORD,'utf8').digest('hex'),12).then(console.log)"`
   خروجی را به عنوان `ADMIN_PASSWORD_HASH` وارد کنید و خود `ADMIN_PASSWORD` را از محیط حذف کنید. رمز را برای هیچ‌کس ارسال نکنید.
6. Deploy کنید. سپس `https://YOUR-SITE.netlify.app/api/health` را باز کنید؛ پاسخ موفق باید `ok: true` و `database: connected` نشان دهد.
7. با یک حساب آزمایشی ثبت‌نام، ورود/خروج، ثبت سفارش و دسترسی پنل ادمین را بررسی کنید. قبل از انتشار نهایی، HTTPS و بکاپ خودکار دیتابیس را تأیید کنید.

## متغیرهای لازم
- `NODE_ENV=production`
- `DATABASE_URL`
- `SESSION_SECRET` (حداقل ۳۲ کاراکتر تصادفی)
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD_HASH` (هش bcrypt از رمز مدیریت، با پیش‌هش SHA-256 طبق دستور بالا)
- `TRUST_PROXY=1` اختیاری؛ فقط اگر تنظیمات پروکسی Netlify به این مقدار نیاز دارد.

## یادداشت‌ها
- متغیرهای محرمانه را فقط در داشبورد Netlify وارد کنید. تغییر متغیرها نیازمند deploy مجدد است.
- Netlify دیتابیس PostgreSQL را به‌عنوان بخشی از این پروژه فراهم نمی‌کند؛ دیتابیس باید در سرویس جداگانه باشد.
- داده‌های نسخه قدیمی که فقط در `localStorage` مرورگر بودند، خودکار منتقل نمی‌شوند؛ پیش از جایگزینی نسخه قدیمی از پنل آن نسخه backup بگیرید.
- این بسته با ساختار Netlify Functions تنظیم شده، اما تا زمانی که به GitHub/Netlify و دیتابیس واقعی وصل و endpointها در محیط منتشرشده آزمایش نشده‌اند، آنلاین و عملیاتی محسوب نمی‌شود.
