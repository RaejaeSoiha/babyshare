# 📂 Free File Share with QR Code

A free, open-source project for sharing files online or offline using QR codes.  
Built with **Node.js + Express**, it supports schools, NGOs, communities, families, and individuals anywhere in the world.

 **100% free — no service charges, no subscriptions.**

---

## 🚀 Features
- Upload and share files instantly  
- Auto-generate QR codes for fast downloads  
- Works both **online** and **offline (LAN / localhost)**  
- AES-256 encrypted file storage  
- Session-based user system  
- Lightweight & open-source  

---

## ⚠️ Before You Start  
### **Run this first (REQUIRED):**
```bash
npm install
```
This installs all required Node.js packages before running the server.

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/free-file-share.git
cd free-file-share
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Create Environment Variables  
Create a file named **`.env`** in the project root:

```env
PORT=3000
FILE_KEY=your-secret-key
SESSION_SECRET=your-session-secret
```

You can change the port or secrets if needed.

---

##  Enable Local HTTPS (Optional but Recommended)

For local development using HTTPS, generate a self-signed certificate:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/selfsigned.key -out certs/selfsigned.crt -days 365
```

This creates:

```
/certs/selfsigned.key  
/certs/selfsigned.crt
```

Your server can now run in HTTPS mode.

---

## ▶️ Start the Server

Run the project with:

```bash
node server.js
```

Then open in your browser:

👉 `http://localhost:3000`  
or  
👉 `https://localhost:3000` (if you enabled HTTPS)

---

## 🐳 Docker Deployment (Recommended)

Using **docker-compose**:

```bash
docker-compose up -d
```

Docker will:
- Build the image  
- Mount `uploads/` for persistent storage  
- Run the server at **port 3000** automatically  

Stop with:

```bash
docker-compose down
```

---

## 📱 How to Use

1. Upload your file(s)  
2. You get a **QR Code**  
3. Scan with any smartphone  
4. Download instantly  

Works **WITHOUT INTERNET** on the same WiFi / LAN network.

---

## 📁 Project Structure

```
.
├── server.js
├── users.json
├── shares.json
├── uploads/
├── certs/              # (optional - created if HTTPS is used)
├── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🤝 Contributing

Pull requests are welcome!  
For major changes, please open an issue to discuss what you'd like to change.

---

## 📜 License

This project is licensed under the **MIT License**.  
Free to use, modify, and distribute for personal.
