# 🛡️ ThreatLens

> **A Comprehensive Cybersecurity Monitoring & Threat Detection Platform**
>
> Real-time security event logging, behavioral anomaly detection, and intelligent threat identification for enterprise organizations.

---

## 📋 Table of Contents

- [The Problem](#-the-problem)
- [Our Solution](#-our-solution)
- [Key Features](#-key-features)
- [Tech Stack](#️-tech-stack)
- [Project Architecture](#-project-architecture)
- [Database Design](#-database-design)
- [Getting Started](#-getting-started)
- [Documentation](#-documentation)
- [Contributors](#-contributors)
- [Credits](#-credits)

---

## 🔴 The Problem

Organizations today face critical cybersecurity challenges:

- **Blind Spots in User Activity**: Without centralized monitoring, unauthorized access and malicious behavior often go undetected.
- **Delayed Threat Response**: Manual security reviews create gaps between when threats occur and when they're identified.
- **Lack of Forensic Trails**: Poor audit logging makes incident investigation time-consuming and incomplete.
- **Behavioral Anomalies Undetected**: Off-hours logins, suspicious IPs, privilege escalations, and concurrent sessions can indicate compromise but are hard to spot.
- **Multi-tenant Complexity**: Managing users across multiple organizations with different roles and permissions is operationally intensive.

**Impact:** Data breaches, compliance violations, and increased security incidents.

---

## ✅ Our Solution

**ThreatLens** is a database-driven cybersecurity platform that solves these challenges through:

| Challenge | Solution |
|-----------|----------|
| Blind spots in activity | Comprehensive real-time event logging & session monitoring |
| Delayed response | Automated threat detection & instant alert system |
| Missing audit trails | Immutable audit logs with full forensic context |
| Undetected anomalies | ML-ready behavioral analysis & rule-based threat flags |
| Multi-tenant overhead | Built-in RBAC, organization isolation, and user permission management |

**Result:** Organizations gain visibility, faster incident response, and auditable security operations.

---

## 🚀 Key Features

### 🔐 **Core Security Capabilities**

- **Organization & User Management**
  - Multi-tenant architecture with complete organization isolation
  - Role-based access control (RBAC) with granular permissions
  - Secure user registration with bcrypt password hashing

- **Real-time Event Logging**
  - Automatically captures all critical security events
  - Rich metadata for forensic investigation
  - Immutable audit trails for compliance

- **Session Monitoring**
  - Tracks all user logins and active sessions
  - Detects concurrent session anomalies
  - Session lifetime and timeout management

- **Advanced Threat Detection**
  - 🚨 **Off-Hours Login Alerts** – Flags suspicious timing patterns
  - 🌍 **Suspicious IP Detection** – Identifies unexpected geographic locations
  - 📈 **Privilege Escalation Tracking** – Monitors role and permission changes
  - 👥 **Concurrent Session Detection** – Catches impossible user behaviors
  - 🔓 **Unauthorized Access Prevention** – Validates permissions on every operation

- **Intelligent Alert Management**
  - Automatic alert generation for critical incidents
  - Alert status tracking (open, investigating, resolved)
  - Historical alert audit trail with automated logging

- **Security Analytics**
  - Analytical queries for trend identification
  - User behavior profiling
  - Risk scoring and incident categorization

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.x with Flask framework |
| **Database** | PostgreSQL (relational, ACID-compliant) |
| **ORM/Access** | psycopg2 (direct database driver) |
| **Security** | bcrypt (password hashing), role-based access control |
| **Configuration** | Environment variables (.env) for secure credential management |

---

## 🏗️ Project Architecture

```
ThreatLens/
│
├── 📁 backend/                     # Application Layer
│   ├── app.py                      # Flask entry point
│   ├── db.py                       # Database connection management
│   ├── routes/                     # API endpoints
│   │   ├── auth_routes.py         # Authentication & registration
│   │   ├── org_routes.py          # Organization management
│   │   ├── user_routes.py         # User management
│   │   ├── event_routes.py        # Event logging & retrieval
│   │   ├── session_routes.py      # Session tracking
│   │   └── threat_routes.py       # Threat detection & alerts
│   ├── requirements.txt            # Python dependencies
│   └── Credentials.env             # Database credentials (gitignored)
│
├── 📁 database/                    # Data Layer
│   ├── schema.sql                 # Complete relational schema
│   ├── triggers.sql               # Automated database triggers
│   ├── queries.sql                # Analytical queries
│   └── seed_data.sql              # Sample data for testing
│
├── 📁 Files/                       # Documentation & Diagrams
│   ├── ThreatLens_ERD.png         # Entity-Relationship Diagram
│   ├── ThreatLens_Complete_Workflow.pdf
│   ├── ThreatLens.docx            # Full project report
│   └── USERS.xlsx                 # Sample datasets
│
└── README.md                       # This file
```

---

## 💾 Database Design Highlights

### **Fully Normalized Relational Schema**

- **Organizations** – Multi-tenant isolation
- **Users** – Complete user profiles with authentication
- **Roles & Permissions** – Fine-grained access control
- **Assets** – IT resources under management
- **Sessions** – Login tracking and activity history
- **Security Events** – Comprehensive event logging
- **Alerts** – Incident tracking and management
- **Audit Logs** – Immutable trail of all system changes

### **Intelligent Automation**

- **Database Triggers** – Automatic audit logging on data changes
- **Event Correlation** – Triggers connect session logins to security events
- **Alert Auditing** – Automatic logging of alert status transitions
- **Data Integrity** – Foreign keys and constraints ensure consistency

### **Analytical Power**

- Pre-built queries for security insights
- User behavior analysis capabilities
- Threat trend identification
- Compliance reporting ready

**ER Diagram:**  
![Database Architecture](Files/ThreatLens_ERD.png)

---

## ⚡ Getting Started

### **Prerequisites**
- Python 3.7+
- PostgreSQL 12+
- Git

### **Installation Steps**

**1. Clone the Repository**
```bash
git clone https://github.com/Usman-Azhar/ThreatLens.git
cd ThreatLens
```

**2. Set Up PostgreSQL Database**
```bash
# Create a new PostgreSQL database
createdb threatlens

# Execute schema files in order
psql -U your_username -d threatlens -f database/schema.sql
psql -U your_username -d threatlens -f database/triggers.sql
psql -U your_username -d threatlens -f database/seed_data.sql
```

**3. Configure Environment Variables**
```bash
# Copy and edit the credentials file
cp backend/Credentials.env.example backend/Credentials.env

# Edit Credentials.env with your database connection details:
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=threatlens
# DB_USER=your_username
# DB_PASSWORD=your_password
```

**4. Install Python Dependencies**
```bash
cd backend
pip install -r requirements.txt
```

**5. Run the Application**
```bash
python app.py
```

The application will start on **http://localhost:5000**

### **API Endpoints Overview**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/auth/register` | POST | User registration |
| `/api/auth/login` | POST | User authentication |
| `/api/organizations` | GET/POST | Organization management |
| `/api/users` | GET/POST | User management |
| `/api/events` | GET/POST | Security event logging |
| `/api/sessions` | GET | Session monitoring |
| `/api/threats` | GET | Threat detection & alerts |

---

## 📚 Documentation

| Document | Location | Purpose |
|----------|----------|---------|
| **Full Project Report** | `Files/ThreatLens.docx` | Complete technical documentation |
| **System Workflow** | `Files/ThreatLens_Complete_Workflow.pdf` | Architecture and data flow diagrams |
| **Database Schema** | `database/schema.sql` | SQL table definitions and relationships |
| **Sample Data** | `Files/USERS.xlsx` | Test data for demonstration |

---

## 🎯 Use Cases

✅ **Enterprise Security Teams** – Monitor user activity across multiple departments  
✅ **Compliance Officers** – Generate auditable security reports  
✅ **Incident Response Teams** – Investigate security incidents with full forensic data  
✅ **System Administrators** – Track privilege escalations and access patterns  
✅ **IT Auditors** – Validate security controls and access reviews  

---

## 🔄 Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] Real-time dashboard with visualizations
- [ ] Integration with SIEM platforms
- [ ] Mobile alert notifications
- [ ] Advanced threat correlation engine
- [ ] Automated response workflows

---

## 👥 Contributors

This project was developed collaboratively by three talented developers:

<table>
<tr>
<td align="center">
<a href="https://github.com/Usman-Azhar">
<img src="https://avatars.githubusercontent.com/u/190142643?v=4" width="100px;" alt="Usman Azhar"/><br />
<sub><b>Usman Azhar</b></sub></a><br />
</td>
<td align="center">
<a href="https://github.com/fatimaalli">
<img src="https://avatars.githubusercontent.com/u/210160015?v=4" width="100px;" alt="Fatima Alli"/><br />
<sub><b>Fatima Alli</b></sub></a><br />
</td>
<td align="center">
<a href="https://github.com/GhostByte101">
<img src="https://avatars.githubusercontent.com/u/205511354?v=4" width="100px;" alt="GhostByte101"/><br />
<sub><b>GhostByte101</b></sub></a><br />
</td>
</tr>
</table>

---

## ❤️ Credits

**Project Type:** University DBMS (Database Management Systems) Semester Project  
**Year:** 2025-2026  
**Institution:** University Project

This project represents a comprehensive DBMS implementation showcasing:
- Relational database design with full normalization
- Backend API development with Python/Flask
- Security best practices (RBAC, password hashing, audit logging)
- Real-world threat detection scenarios
- Production-ready code architecture

---

## 📄 License

This project is provided for educational and organizational purposes.

---

**🛡️ ThreatLens – Making Organizations Secure by Design**
