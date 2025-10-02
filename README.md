# 📂 Free File Share with QR Code

A free, open-source project for sharing files online or offline via QR codes.  
Built with **Node.js + Express**, it supports schools, NGOs, communities, families, and individuals anywhere in the world.

🔥 Ready to use for **schools, NGOs, communities, families, and individuals** with **no service charge**.

---

## 🚀 Features
- Upload and share files easily
- Generate QR codes for file download
- Works both **online** and **offline (LAN / localhost)**
- Secure encryption with AES-256
- Session-based user management
- 100% free and open-source

---

## 📦 Installation

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/free-file-share.git
cd free-file-share
```

### 2. Install dependencies
```bash
npm install
```

### 3. Environment variables
Create a `.env` file in the root:
```env
PORT=3000
FILE_KEY=your-secret-key
SESSION_SECRET=your-session-secret
```

### 4. Local HTTPS Set (Self-Signed Certificates)
``` For local testing with HTTPS, generate a self-signed certificate: 
run:

mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/selfsigned.key -out certs/selfsigned.crt -days 365



### 5. Run the server
```bash
node server.js
```

Then open:  
👉 `http://localhost:3000`

---

## 🐳 Docker Deployment

With **docker-compose** (recommended):

```bash
docker-compose up -d
```

This will:
- Build the container
- Run your server at port **3000**
- Mount the `uploads` folder for persistent storage

---

## 📱 Usage
1. Upload your file(s)
2. Get a **QR code**
3. Scan with any phone to download the file instantly

Works **without internet** on the same LAN network.

---

## 📂 Project Structure
```
.
├── server.js
├── users.json
├── shares.json
├── uploads/
├── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first.

---

## 📜 License
This project is licensed under the MIT License.  
Free to use, modify, and share.
