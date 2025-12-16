# ☁️ SecureDrive: Your Personal Cloud Storage Solution

### File Store Locally | Full-Stack MERN Application

[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![React](https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

---

## 📝 Project Overview

SecureDrive is a modern, full-stack cloud storage application built with the MERN stack. It provides a secure and scalable platform for users to manage, organize, and share their digital files and folders with an emphasis on a clean, real-time user experience.

---

## ✨ Live Demo / Preview

> **🖼️ Add Your Demo Here:** To make your README shine, replace this placeholder with a GIF or a video link showing the application in action (e.g., login, file upload, folder creation).

**[ ADD YOUR DEMO GIF/ANIMATION HERE ]**

---

## 🚀 Key Features

A comprehensive suite of tools for robust file management:

### Security & Authentication
* 🔒 **Robust Authentication:** Secure user registration, login, and session management using JSON Web Tokens (JWT) and `bcryptjs`.
* 🔑 **Google OAuth 2.0:** Seamless integration for quick and easy social sign-in.
* 🛡️ **Unauthorized Access Prevention:** Strict backend checks ensure data is accessible only by the owning user or via a valid share link.
* 🚦 **Security Focus:** Enhanced security headers and network compression via `helmet` and `compression`.

### File Management
* 📁 **Full File Explorer:** Create, rename, move, and delete files and folders with intuitive controls.
* 📤 **Secure Multi-File Upload:** Handle multiple uploads simultaneously with real-time progress and preview support.
* 🔗 **Permission-Based Sharing:** Generate public, read-only links for files and folders, allowing controlled external access.
* 🗑️ **Recycle Bin (Trash):** Functionality for soft-deletion, allowing files to be restored or permanently deleted.

### Architecture & UX
* ⚙️ **Modular & Scalable REST API:** A well-structured backend designed for maintainability and growth.
* 🔄 **Real-Time UI Updates:** The frontend delivers a responsive experience with immediate feedback on file operations.

---

## 💻 Tech Stack

### Backend (`drive-backend`)
| Category | Technology | Key Dependencies |
| :--- | :--- | :--- |
| **Runtime** | Node.js | `express` |
| **Database** | MongoDB | `mongoose` |
| **Authentication** | JWT, Google OAuth | `jsonwebtoken`, `passport-jwt`, `passport-google-oauth20`, `bcryptjs` |
| **File Handling** | File Uploads | `multer` |
| **Validation** | Data Integrity | `express-validator` |

### Frontend (`drive-frontend`)
| Category | Technology | Key Dependencies |
| :--- | :--- | :--- |
| **Framework** | React | `react`, `react-dom` |
| **Styling** | Utility-First CSS | `tailwindcss`, `autoprefixer` |
| **Build Tool** | Modern Bundler | `Vite` |
| **Routing** | Declarative Routing | `react-router-dom` |
| **Networking** | HTTP Client | `axios` |
| **Icons** | Clean Icons | `lucide-react` |

---

## ⚙️ Getting Started

Follow these steps to get your development environment running locally.

### 📋 Prerequisites

You will need the following installed:

* [Node.js](https://nodejs.org/) (LTS version recommended)
* A running instance of **MongoDB** (local or cloud-based like Atlas)
* **Google API Credentials** (Client ID and Secret) for the OAuth features.

### 1. Backend Setup

Start by configuring and running the Node.js/Express server.

1.  Navigate to the backend directory:
    ```bash
    cd drive-backend
    ```

2.  Install all backend dependencies:
    ```bash
    npm install
    ```

3.  Create a file named `.env` in the `drive-backend` directory and add your configurations:
    ```
    # --- Server Configuration ---
    PORT=5000 
    CLIENT_URL=http://localhost:3000 

    # --- Database Configuration ---
    MONGODB_URI=<Your_MongoDB_Connection_String>

    # --- Authentication / Security ---
    JWT_SECRET=<A_Very_Long_Random_String_For_JWT_Signing>
    
    # --- Google OAuth Configuration ---
    GOOGLE_CLIENT_ID=<Your_Google_Client_ID>
    GOOGLE_CLIENT_SECRET=<Your_Google_Client_Secret>
    GOOGLE_CALLBACK_URL=/api/auth/google/callback 
    ```

4.  Start the backend server:
    ```bash
    npm start
    # Server running on http://localhost:5000 
    ```

### 2. Frontend Setup

Next, set up the React application.

1.  Navigate to the frontend directory:
    ```bash
    cd ../drive-frontend
    ```

2.  Install all frontend dependencies:
    ```bash
    npm install
    ```

3.  Create a file named `.env` in the `drive-frontend` directory to link to your backend API:
    ```
    VITE_API_URL=http://localhost:5000/api 
    ```

4.  Start the frontend application:
    ```bash
    npm run dev
    # Application typically opens on http://localhost:5173
    ```

Your full-stack application is now ready!
