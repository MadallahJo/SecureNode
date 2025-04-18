const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const validator = require('validator');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');

// إعداد
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// DOMPurify in Node via jsdom
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// إعدادات الحماية
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
  }
}));

// قراءة البيانات المرسلة
app.use(express.urlencoded({ extended: true }));
app.use(express.static('views'));

// الصفحة الرئيسية
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

// معالجة النموذج
app.post('/submit', async (req, res) => {
  const { password, bio } = req.body;
  const secret = process.env.SECRET_KEY;

  // التحقق والتنظيف
  const cleanBio = DOMPurify.sanitize(bio);
  const sanitizedPassword = validator.escape(password.trim());

  if (!validator.isStrongPassword(sanitizedPassword)) {
    return res.send('❌ كلمة المرور ضعيفة. يجب أن تحتوي على 8 أحرف على الأقل ورقم.');
  }

  const combined = sanitizedPassword + secret;
  const hash = await bcrypt.hash(combined, 10);

  res.send(`
    ✅ تم استلام البيانات بنجاح<br>
    🔒 كلمة المرور المشفرة: <code>${hash}</code><br>
    🧽 السيرة الذاتية المنظفة: <div>${cleanBio}</div>
    <br><a href="/">الرجوع</a>
  `);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
