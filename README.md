# 📂File Store locally (MERN Stack)

[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![React](https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)

## 📝 Description

This repository contains a full-stack cloud storage application designed for secure file and folder management. It provides essential features like robust authentication, file uploads, folder organization, and link-based sharing, all built on the MERN (MongoDB, Express, React, Node.js) stack.

---

## ✨ Live Demo / Animation

> **ACTION REQUIRED:** To make your README look great as requested, replace the placeholder text below with a GIF or a short video demonstrating the application's core functionality (e.g., login, file upload, folder creation).
>
> **Example Markdown for adding your GIF:**
> `![Application Demo](https://raw.githubusercontent.com/your-username/your-repo/main/assets/demo.gif)`

**[ ADD YOUR DEMO GIF/ANIMATION HERE ]**

---

## 🚀 Features

The application is built with a comprehensive set of features for a modern file management experience:

* **Robust Authentication:** User registration, login, and secure session management using JSON Web Tokens (JWT).
* **Google OAuth 2.0:** Seamless social login integration for quick access.
* **File and Folder Management:** Create, rename, move, and delete files and folders.
* **Secure File Uploads:** Uses `multer` on the backend for handling file data.
* **Link Sharing:** Generate public, read-only links to share files and folders with others.
* **Trash/Recycle Bin:** Temporarily store deleted items, allowing for recovery or permanent deletion.
* **Security Focus:** Enhanced security headers and compression implemented using `helmet` and `compression`.

## 🛠️ Tech Stack

### Backend (`drive-backend`)
| Category | Technology | Key Dependencies |
| :--- | :--- | :--- |
| **Runtime** | Node.js | `express` |
| **Database** | MongoDB | `mongoose` |
| **Authentication** | JWT, Google OAuth | `jsonwebtoken`, `passport-jwt`, `passport-google-oauth20`, `bcryptjs` |
| **File Handling** | File Uploads | `multer` |
| **Dev Tools** | Live Reload | `nodemon` |

### Frontend (`drive-frontend`)
| Category | Technology | Key Dependencies |
| :--- | :--- | :--- |
| **Framework** | React | `react`, `react-dom` |
| **Build Tool** | Vite | `@vitejs/plugin-react` |
| **Styling** | Tailwind CSS | `tailwindcss`, `autoprefixer` |
| **Networking** | HTTP Client | `axios` |
| **Icons** | Icons Library | `lucide-react` |

---

## ⚙️ Getting Started

Follow these steps to set up the project locally.

### Prerequisites

* Node.js (LTS recommended)
* MongoDB Instance (local or cloud like MongoDB Atlas)
* Google API Credentials (if using Google OAuth)

### 1. Backend Setup

1.  Navigate to the backend directory:
    ```bash
    cd drive-backend
    ```

2.  Install the required dependencies:
    ```bash
    npm install
    ```

3.  Create a `.env` file in the `drive-backend` directory and configure the environment variables:
    ```
    # --- Server Configuration ---
    PORT=5000 
    CLIENT_URL=http://localhost:3000 # Your frontend URL

    # --- Database Configuration ---
    MONGODB_URI=<Your_MongoDB_Connection_String>

    # --- Authentication / Security ---
    JWT_SECRET=<A_Long_Random_String_For_JWT_Signing>
    
    # --- Google OAuth Configuration ---
    GOOGLE_CLIENT_ID=<Your_Google_Client_ID>
    GOOGLE_CLIENT_SECRET=<Your_Google_Client_Secret>
    GOOGLE_CALLBACK_URL=/api/auth/google/callback 
    ```

4.  Start the backend server:
    ```bash
    npm start
    ```
    The server will run on `http://localhost:5000` (or your specified PORT).

### 2. Frontend Setup

1.  Navigate to the frontend directory:
    ```bash
    cd ../drive-frontend
    ```

2.  Install the required dependencies:
    ```bash
    npm install
    ```

3.  Create a `.env` file in the `drive-frontend` directory and configure the API URL:
    ```
    VITE_API_URL=http://localhost:5000/api 
    ```

4.  Start the frontend application:
    ```bash
    npm run dev
    ```
    The frontend will typically run on `http://localhost:5173` or `http://localhost:3000`.

You are now ready to use the application!
