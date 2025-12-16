# ☁️ SecureDrive: Your Personal Cloud Storage Solution

### File Store Locally | Full-Stack MERN Application

[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![React](https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)

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

---

## 💻 Backend API Endpoints

All endpoints are prefixed with `/api/`. **Access** is either **Public** (no authentication required) or **Private** (requires a valid JWT in the `Authorization: Bearer <token>` header).

### 1. Authentication (`/api/auth`)

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/register` | Register a new user with name, email, and password. | Public |
| `POST` | `/login` | Authenticate and log in a user (returns JWT). | Public |
| `GET` | `/me` | Get the current authenticated user's details. | Private |
| `GET` | `/google` | Initiate Google OAuth process. | Public |
| `GET` | `/google/callback` | Google OAuth callback URL. | Public |
| `POST` | `/logout` | Log out the current user (revokes session/token). | Private |

### 2. File Operations (`/api/files`)

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/upload` | Upload a new file (uses `multer` for `file` field). | Private |
| `GET` | `/` | Get list of user files (supports filtering, pagination, search). | Private |
| `GET` | `/:fileId` | Get metadata for a specific file. | Private |
| `GET` | `/:fileId/download` | Download a file. | Private |
| `GET` | `/:fileId/view` | View a file inline in the browser. | Private |
| `PUT` | `/:fileId/rename` | Rename a file or update its description. | Private |
| `PUT` | `/:fileId/move` | Move a file to a different folder. | Private |
| `PUT` | `/:fileId/remove-from-folder` | Move a file to the root directory. | Private |
| `DELETE`| `/:fileId` | Delete a file (moves to trash). | Private |
| `PUT` | `/:fileId/share` | Toggle public sharing status for a file. | Private |

### 3. File Sharing (Public Access) (`/api/files`)

These routes allow public access to shared files.

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/shared/:shareToken` | Get file metadata for a publicly shared file. | Public |
| `GET` | `/shared/:shareToken/download` | Download a publicly shared file. | Public |

### 4. Folder Operations (`/api/folders`)

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/` | Create a new folder. | Private |
| `GET` | `/` | Get list of user folders. | Private |
| `GET` | `/:folderId` | Get details for a specific folder. | Private |
| `PUT` | `/:folderId` | Update a folder (e.g., rename). | Private |
| `DELETE`| `/:folderId` | Delete a folder (moves to trash). | Private |

### 5. Trash Management (`/api/trash`)

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/move` | Move a file or folder to the trash. | Private |
| `POST` | `/restore` | Restore a file or folder from the trash. | Private |
| `DELETE`| `/delete` | Permanently delete a file or folder from the trash. | Private |
| `DELETE`| `/empty` | Permanently empty the entire trash bin. | Private |
| `GET` | `/` | Get list of items currently in the trash. | Private |

### 6. Share Link Generation (`/api/share`)

These routes handle the creation and management of advanced share links (with potential passwords/expirations).

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/` | Generate a new, specific share link for a file. | Private |
| `GET` | `/` | Get a list of the user's active share links. | Private |
| `GET` | `/:token` | Redirects to the front-end view page for the shared content. | Public |
| `GET` | `/:token/info` | Get public metadata for a password-protected/private share token. | Public |
| `POST` | `/:token/download` | Download a shared file (allows password submission). | Public |
| `DELETE`| `/:shareId` | Revoke a specific share link. | Private |



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

```init
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

```

### --- File Storage (Example) ---
### This is a placeholder, actual implementation details will vary
### For development, files are likely stored locally by Multer




