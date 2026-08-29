# ChatBuz — Cloudflare version

هذه النسخة تحول Backend الموجود في Railway إلى Cloudflare Worker + D1.
تم الحفاظ على عقد API `/api/v1/...` حتى يبقى تطبيق الهاتف متوافقًا قدر الإمكان.

## ما تم تغييره
- PostgreSQL/`pg` -> Cloudflare D1 (SQLite).
- Express server/listen -> Cloudflare Worker `fetch`.
- `jsonwebtoken` -> HS256 باستخدام Web Crypto.
- المعاملات الخاصة بإرسال الهدايا تستخدم `DB.batch()` مع تحديث رصيد مشروط.
- تم الحفاظ على التسجيل، الدخول، المستخدم الحالي، البحث، الغرف، الأعضاء، الرسائل، الهدايا، السجل، وإدارة التطبيق الموجودة في نسخة API.
- لا يوجد اعتماد على Railway داخل Worker.

## النشر
1. ثبّت Node.js 20+.
2. داخل هذا المجلد:
   `npm install`
3. سجّل الدخول:
   `npx wrangler login`
4. أنشئ D1:
   `npx wrangler d1 create chatbuz-db`
5. انسخ `database_id` الناتج إلى `wrangler.toml`.
6. نفّذ المخطط:
   `npx wrangler d1 execute chatbuz-db --remote --file=src/schema.d1.sql`
7. أنشئ سر JWT:
   `npx wrangler secret put JWT_SECRET`
8. انشر:
   `npx wrangler deploy`

بعد النشر سيكون لديك رابط Worker مثل:
`https://chatbuz-api.<subdomain>.workers.dev`

## حساب المالك
لإنشاء حساب المالك يمكن إضافة مسار bootstrap لاحقًا أو تنفيذ seed آمن. لا تضع كلمة المرور داخل Git.
النسخة الحالية لا تنشئ مالكًا تلقائيًا من متغير بيئة حتى لا يتم إنشاء/تغيير كلمة مرور المالك عند كل طلب.

## تطبيق الهاتف
غيّر عنوان الـAPI في تطبيق الهاتف من عنوان Railway إلى:
`https://chatbuz-api.<subdomain>.workers.dev`
أو الأفضل بعد ربط الدومين:
`https://api.chatbuz.com`

## التخزين
الـAPI الحالي يخزن `coverUrl` كرابط فقط ولا يحتوي endpoint رفع ملفات. لذلك لا توجد حاجة لإجبار R2 في عملية النقل الحالية.
إذا كان التطبيق يحتاج رفع صور/ملفات من الهاتف، أضف R2 ثم endpoint upload/presigned URL.

## مهم
هذه النسخة لا تنقل بيانات PostgreSQL القديمة تلقائيًا. إذا كانت قاعدة Railway تحتوي مستخدمين/غرف/رسائل/نقاط مهمة، يجب عمل migration من PostgreSQL إلى D1 قبل تحويل التطبيق نهائيًا.
