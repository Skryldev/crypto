<div dir="rtl">

# 📦 ماژول Go Crypto

یک ماژول رمزنگاری **(Crypto/Encryption)** در زبان **Go** که با تمرکز بر امنیت، کارایی (Performance)، توسعه‌پذیری و رعایت استانداردهای حرفه‌ای مهندسی نرم‌افزار طراحی شده است.


#### این ماژول مناسب استفاده در:

- Backend Serviceها
- Microservices
- سیستم‌های ذخیره‌سازی امن
- Secret Management
- Encryption Layer برای داده‌های حساس
- فایل‌های بزرگ (Streaming Encryption)

---

## 🎯 اهداف طراحی
#### این ماژول با اهداف زیر طراحی شده است:
- رعایت idiomatic Go
- استفاده از best practiceهای مدرن رمزنگاری
- حداقل API Surface ولی قدرتمند
- قابلیت افزودن الگوریتم‌های جدید بدون شکستن API
- استفاده از Authenticated Encryption
- مدیریت صحیح nonce و salt
- جلوگیری از الگوریتم‌های ناامن یا deprecated
- کارایی بالا و حداقل allocation غیرضروری
- پشتیبانی از streaming برای داده‌های بزرگ
- قابلیت Versioning برای backward compatibility

---
## 🔐 الگوریتم‌های استفاده‌شده
## 🔧 قابلیت‌ها و تکنولوژی‌ها

| قابلیت | تکنولوژی | توضیحات و دلیل استفاده |
|---------|----------|----------------------|
| Symmetric Encryption | AES-256-GCM | الگوریتم رمزنگاری متقارن با امنیت بالا و پشتیبانی از Authenticated Encryption (حفظ محرمانگی و صحت داده‌ها). مناسب برای داده‌های حساس. |
| Key Derivation | PBKDF2 (SHA-256) | مشتق‌سازی امن کلید از پسورد، جلوگیری از brute-force و dictionary attack. استفاده از SHA-256 باعث افزایش مقاومت می‌شود. |
| Random | crypto/rand | تولید عدد تصادفی امن برای nonce، salt و کلیدها. استفاده از secure random باعث جلوگیری از پیش‌بینی‌پذیری می‌شود. |
| Encoding | base64 | تبدیل داده‌های باینری به رشته برای ذخیره یا انتقال امن، بدون دست‌کاری محتوا. |
| AEAD | cipher.AEAD | Authenticated Encryption with Associated Data. تضمین می‌کند داده رمزنگاری شده تغییر نکرده و احراز اصالت انجام شده است. |
---
## 🔑 بخش اول: تولید کلید (Key Generation)
### تولید کلید تصادفی 256 بیتی

<div dir="ltr">

```go
keyGen := crypto.DefaultKeyGenerator{}

key, err := keyGen.Generate(32) // 32 bytes = 256 bit
if err != nil {
panic(err)
}
```

<div dir="rtl">

## 🔐 بخش دوم: رمزنگاری و رمزگشایی ساده
### ساخت AES-GCM

<div dir="ltr">

```go
ctx := context.Background()
cipher, err := crypto.NewAESGCM(key)
if err != nil {
panic(err)
}
```

<div dir="rtl">

## Encrypt کردن داده

<div dir="ltr">

```go
plaintext := []byte("پیام محرمانه")
ciphertext, err := cipher.Encrypt(ctx, plaintext, nil)

if err != nil {
panic(err)
}
```

<div dir="rtl">

## Decrypt کردن داده

<div dir="ltr">

```go
decrypted, err := cipher.Decrypt(ctx, ciphertext, nil)
if err != nil {
panic(err)
}

fmt.Println(string(decrypted))
```

<div dir="rtl">

## 🔒 استفاده از AAD (Additional Authenticated Data)
#### AAD داده‌ای است که رمز نمی‌شود ولی در احراز اصالت دخیل است.

<div dir="ltr">

```go
aad := []byte("user-id-123")

ciphertext, _ := cipher.Encrypt(ctx, plaintext, aad)

decrypted, _ := cipher.Decrypt(ctx, ciphertext, aad)
```

<div dir="rtl">

##### اگر AAD متفاوت باشد Decrypt خطا خواهد داد.
## 🔐 بخش سوم: Password-Based Encryption (PBKDF2)
### اگر بخواهید به جای کلید خام از password استفاده کنید:
#### 1️⃣ تولید Salt

<div dir="ltr">

```go
salt, err := crypto.GenerateSalt()
if err != nil {
panic(err)
}
```

<div dir="rtl">

#### 2️⃣ مشتق‌سازی کلید از پسورد

<div dir="ltr">

```go
password := []byte("strong-password")

derivedKey := crypto.DeriveKey(
  password,
  salt,
  crypto.DefaultIter,
  crypto.DefaultKeySize,
)
```

<div dir="rtl">

#### 3️⃣ استفاده از کلید مشتق‌شده

<div dir="ltr">

```go
cipher, _ := crypto.NewAESGCM(derivedKey)
plaintext, _ := cipher.Decrypt(ctx, ciphertext, nil)
```

<div dir="rtl">

##### ⚠ نکته مهم: Salt باید ذخیره شود تا هنگام Decrypt مجدداً همان کلید تولید شود.
## 📡 بخش چهارم: Streaming Encryption (برای فایل‌های بزرگ)
#### برای رمزنگاری فایل‌های حجیم:
##### Encrypt Stream:

<div dir="rtl">

```go
inputFile, _ := os.Open("input.txt")
outputFile, _ := os.Create("encrypted.bin")

defer inputFile.Close()
defer outputFile.Close()

err := crypto.EncryptStream(cipher, inputFile, outputFile)
if err != nil {
panic(err)
}
```

<div dir="rtl">

##### Decrypt Stream:

<div dir="rtl">

```go
encFile, _ := os.Open("encrypted.bin")
decFile, _ := os.Create("decrypted.txt")
defer encFile.Close()
defer decFile.Close()

err := crypto.DecryptStream(cipher, encFile, decFile)
if err != nil {
    panic(err)
}
```

<div dir="rtl">

###### این روش:
- توضیح: هر chunk جداگانه رمزگشایی می‌شود تا حافظه اشباع نشود.
- حافظه را اشباع نمی‌کند
- chunk-based است
- مناسب فایل‌های چند گیگابایتی

## 🧠 نکات امنیتی مهم
- ✔ از AES-256-GCM استفاده می‌شود
- ✔ Nonce به صورت امن تولید می‌شود
- ✔ از crypto/rand استفاده شده
- ✔ از الگوریتم deprecated استفاده نشده
- ✔ از AEAD استفاده شده (Confidentiality + Integrity)
- ✔ مقایسه‌ها constant-time هستند
- ✔ API سطح حمله کوچک دارد
## 🔐 Best Practices پیشنهادی
- هرگز کلید را hardcode نکنید
- کلیدها را در KMS یا Vault نگهداری کنید
- از rotation دوره‌ای استفاده کنید
- Salt و Version را ذخیره کنید
- برای production از Argon2id (در صورت نیاز) استفاده کنید
- کلیدها را در log چاپ نکنید
## 📌 سناریو کامل آموزشی (End-to-End)

<div dir="ltr">

```go
func main() {
	ctx := context.Background()

	fmt.Println("=== 🔐 مثال جامع ماژول Crypto ===")

	// 1️⃣ تولید کلید تصادفی
	keyGen := crypto.DefaultKeyGenerator{}
	key, _ := keyGen.Generate(32) // 256-bit key

	// 2️⃣ ساخت AES-GCM cipher با کلید
	cipher, _ := crypto.NewAESGCM(key)

	// 3️⃣ پیام اصلی و AAD
	plaintext := []byte("سلام! این یک پیام محرمانه است.")
	aad := []byte("user-id-123")

	// 4️⃣ Encrypt معمولی
	ciphertext, _ := cipher.Encrypt(ctx, plaintext, aad)
	fmt.Println("Ciphertext (Base64):", crypto.ToBase64(ciphertext))

	// 5️⃣ Decrypt معمولی
	decrypted, _ := cipher.Decrypt(ctx, ciphertext, aad)
	fmt.Println("Decrypted:", string(decrypted))

	// 6️⃣ استفاده از PBKDF2 برای پسورد
	password := []byte("strong-password")
	salt, _ := crypto.GenerateSalt()
	derivedKey := crypto.DeriveKey(password, salt, crypto.DefaultIter, crypto.DefaultKeySize)
	cipherFromPassword, _ := crypto.NewAESGCM(derivedKey)

	pbeCiphertext, _ := cipherFromPassword.Encrypt(ctx, plaintext, aad)
	pbeDecrypted, _ := cipherFromPassword.Decrypt(ctx, pbeCiphertext, aad)
	fmt.Println("PBKDF2 Decrypted:", string(pbeDecrypted))

	// 7️⃣ Wrap کردن ciphertext در envelope versioned
	wrapped := crypto.Wrap(crypto.Version1, ciphertext)
	env, _ := crypto.Unwrap(wrapped)
	fmt.Printf("Envelope Version: %x, Data Length: %d\n", env.Version, len(env.Data))

	// 8️⃣ Base64 encode/decode
	encoded := crypto.ToBase64(ciphertext)
	decoded, _ := crypto.FromBase64(encoded)
	fmt.Println("Decoded Base64 matches original?", string(decoded) == string(ciphertext))

	// 9️⃣ Streaming Encryption / Decryption (فایل‌های بزرگ)
	// ایجاد فایل ورودی برای مثال
	os.WriteFile("input.txt", plaintext, 0644)
	inputFile, _ := os.Open("input.txt")
	encryptedFile, _ := os.Create("encrypted.bin")
	defer inputFile.Close()
	defer encryptedFile.Close()

	// EncryptStream
	err := crypto.EncryptStream(cipher, inputFile, encryptedFile)
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ فایل رمزنگاری شد: encrypted.bin")

	// DecryptStream
	encFile, _ := os.Open("encrypted.bin")
	decFile, _ := os.Create("decrypted.txt")
	defer encFile.Close()
	defer decFile.Close()

	err = crypto.DecryptStream(cipher, encFile, decFile)
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ فایل رمزگشایی شد: decrypted.txt")

	// خواندن خروجی برای بررسی
	decryptedFile, _ := os.ReadFile("decrypted.txt")
	fmt.Println("Decrypted file content:", string(decryptedFile))
}
```

<div dir="rtl">

### 💡 نکات مهم:

1. **Encryption همیشه همراه با AEAD** انجام شود تا صحت و محرمانگی تضمین شود.  
2. **Streaming Encryption** فقط برای داده‌های بزرگ کاربرد دارد.  
3. **Envelope Versioned** و **Key Rotation** برای سیستم‌های Enterprise و long-lived data ضروری است.  
4. **Base64 / Hex** صرفاً برای storage/transfer استفاده می‌شود، خود encryption نیست.  
5. **PBKDF2 / Argon2id** برای تولید کلید از پسورد و جلوگیری از brute-force.  
6. **Plug-able Cipher Interface** امکان توسعه الگوریتم‌ها بدون شکستن API را فراهم می‌کند.  
7. **AES-GCM و AEAD** بهترین روش symmetric encryption برای داده‌های حساس است.  
2. **Envelope Versioned** برای key rotation و آینده‌نگر بودن ضروری است.  
3. **PBKDF2 / Argon2id** تنها روش مناسب برای پسورد یا derivation از password است.  
4. **Base64** فقط encoding است و امنیت اضافه نمی‌کند، فقط برای انتقال یا storage رشته‌ای کاربرد دارد.  
5. **Streaming Encryption** برای داده‌های بزرگ و فایل‌های حجیم حیاتی است.  
6. Nonce و Salt برای هر encrypt/derive باید منحصر به فرد باشند.  
7. کلیدها نباید در کد hardcoded باشند؛ از **Vault / KMS / HSM** استفاده کنید.  

---
# 🏁 جمع‌بندی
## 🔐 انتخاب روش رمزنگاری داده‌ها برای DB

| نوع داده | حجم/اندازه | روش پیشنهادی | جزئیات و نکات امنیتی | استفاده از Base64 | Versioned Envelope | Streaming |
|----------|-----------|---------------|----------------------|-----------------|------------------|-----------|
| Access Token | کوچک (<1KB) | AES-GCM Encrypt | AEAD تضمین محرمانگی و صحت، کلید از KMS/Vault | ✅ اگر DB رشته‌ای است | اختیاری | ❌ |
| Refresh Token | کوچک (<1KB) | AES-GCM Encrypt + Envelope Versioned | امکان key rotation و backward compatibility، ذخیره metadata | ✅ | ✅ | ❌ |
| Password (User) | کوچک | PBKDF2 / Argon2id → Store hash | هیچوقت plaintext ذخیره نشود، salt منحصر به فرد برای هر کاربر | ❌ | ❌ | ❌ |
| Short Secrets (API Keys) | کوچک | AES-GCM Encrypt | AEAD برای integrity | ✅ | اختیاری | ❌ |
| Large JSON / Blob / Logs | بزرگ (>1MB) | EncryptStream | chunk-based، memory-efficient، integrity هر chunk حفظ می‌شود | ✅ برای انتقال / storage رشته‌ای | اختیاری | ✅ |
| PDF / Document / Binary Files | بزرگ (>1MB) | EncryptStream | مناسب ذخیره در Object Storage، memory-efficient | ✅ اختیاری | اختیاری | ✅ |
| Critical / Sensitive Data | کوچک تا متوسط | AES-GCM Encrypt + Envelope Versioned | نسخه‌بندی، key rotation، metadata برای آینده | ✅ | ✅ | ❌ |
| Data with Context (AAD) | کوچک تا متوسط | AES-GCM Encrypt + AAD | تضمین integrity همراه با context اضافی | ✅ | اختیاری | ❌ |


### 🔑 نکات حرفه‌ای:

1. **کلیدها جدا از DB ذخیره شوند** (Vault / KMS / HSM)  
2. **Nonce و Salt** برای هر داده منحصر به فرد باشند  
3. **Base64** فقط برای storage یا انتقال رشته‌ای استفاده شود  
4. **Streaming Encryption** برای فایل‌ها و داده‌های بزرگ الزامی است  
5. **Versioned Envelope** برای data lifecycle طولانی یا حساس توصیه می‌شود  
6. **PBKDF2 / Argon2id** برای پسوردها یا derivation از password امن‌ترین روش است  

💡 خلاصه ذهنی:  

- داده کوچک → Encrypt معمولی + Base64 کافی است  
- داده حساس و طولانی‌مدت → Envelope Versioned + AES-GCM  
- فایل یا blob بزرگ → Streaming Encryption  
- پسورد → Hash امن (PBKDF2/Argon2id)  


##### این ماژول:
- امن (Secure by Default)
- سریع (High Performance)
- توسعه‌پذیر (Extensible)
- versioned
- production-ready
- سیستم‌های
##### مناسب برای هر backend engineer که نیاز به یک لایه رمزنگاری استاندارد و قابل اتکا دارد.
