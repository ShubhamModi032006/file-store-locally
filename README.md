# ☁️ SecureDrive: Your Personal Cloud Storage Solution

### File Store Locally | Full-Stack MERN Application

[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![React](https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

---
## ✨ Overview

MyDrive is a modern, full-stack application designed to emulate the core functionality of popular cloud storage services like Google Drive or Dropbox. It allows users to securely store, organize, and share their files and folders.

The application is built with a powerful **MERN stack (MongoDB, Express, React, Node.js)** architecture, ensuring a fast, scalable, and robust experience.

## 💡 Key Features

* **Authentication:** Secure registration, login, and Google OAuth integration.
* **File Management:** Upload, download, view, rename, and delete files.
* **Folder Organization:** Create, view, rename, and delete custom folders.
* **Trash System:** Move files/folders to trash and restore them, or permanently delete them.
* **File Sharing:** Generate public, revocable, and optionally password-protected share links.
* **Search & Filtering:** Easily locate files by name or filter by type (image, document, video, etc.).
* **Modern UI:** Built with React and styled using the utility-first framework, Tailwind CSS.

## 🖼️ Demo (Animation Placeholder)

*(You can replace the placeholder text below with a GIF or animated screenshot demonstrating the main features like file upload, folder creation, and sharing. This will significantly improve the visual appeal of your README.)*

[Insert GIF/Animation of the Application Dashboard Here]


## 🛠️ Tech Stack

### Backend (`drive-backend`)
| Category | Technology | Key Dependencies |
| :--- | :--- | :--- |
| **Runtime** | Node.js | - |
| **Framework** | Express | `express`, `compression`, `helmet`, `cors` |
| **Database** | MongoDB | `mongoose` |
| **Auth** | JWT / OAuth 2.0 | `jsonwebtoken`, `bcryptjs`, `passport`, `passport-google-oauth20`, `passport-jwt` |
| **Validation** | Data Validation | `express-validator` |
| **File Handling** | File Uploads | `multer` |

### Frontend (`drive-frontend`)
| Category | Technology | Key Dependencies |
| :--- | :--- | :--- |
| **Framework** | React | `react`, `react-dom` |
| **Build Tool** | Vite | `@vitejs/plugin-react` |
| **Styling** | Tailwind CSS | `tailwindcss`, `autoprefixer`, `postcss` |
| **Routing** | React Router | `react-router-dom` |
| **HTTP Client** | API Calls | `axios` |
| **Icons** | Icon Library | `lucide-react` |

## 🚀 Getting Started

### Prerequisites

Before running the application, ensure you have the following installed:

* Node.js (v18+)
* MongoDB (or a connection string for MongoDB Atlas)
* Git

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <repo-name>
    ```

2.  **Backend Setup (`drive-backend`)**

    ```bash
    cd drive-backend
    npm install
    # Create a .env file (see Environment Variables section)
    npm start 
    # or for development: npm run dev (if nodemon is configured)
    ```

3.  **Frontend Setup (`drive-frontend`)**

    ```bash
    cd ../drive-frontend
    npm install
    npm run dev
    ```

The backend server will run on `http://localhost:5000` (or your defined port), and the frontend will typically be accessible at `http://localhost:5173`.

### Environment Variables

Create a file named `.env` in the `drive-backend` directory and populate it with your configuration:

```ini
# --- General ---
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173

# --- MongoDB ---
MONGO_URI=mongodb://127.0.0.1:27017/mydrive

# --- JWT/Security ---
JWT_SECRET=YOUR_VERY_SECRET_KEY
JWT_EXPIRATION=1d 

# --- Google OAuth 2.0 (For Passport) ---
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
GOOGLE_CALLBACK_URL=http://localhost:5000/api/auth/google/callback

# --- File Storage (Example) ---
# This is a placeholder, actual implementation details will vary
# For development, files are likely stored locally by Multer

