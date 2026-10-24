# Library Inventory System

A database-backed **Library Inventory and Loan Management System** built with **Python, Flask, SQLite, and pytest**.

The system supports CRUD operations, book search and filtering, role-based user actions, borrowing and returning books, dashboard statistics, a simple frontend UI, and automated testing.

---

## Features

### Authentication and Roles

The system has three user roles:

- **Admin**
- **Librarian**
- **Member**

Each role has different permissions.

| Feature | Member | Librarian | Admin |
|---|---:|---:|---:|
| Browse books | Yes | Yes | Yes |
| Search/filter books | Yes | Yes | Yes |
| Borrow books | Yes | Yes | Yes |
| View own loans | Yes | Yes | Yes |
| Add/edit books | No | Yes | Yes |
| Return books | No | Yes | Yes |
| View all loans | No | Yes | Yes |
| Manage users | No | No | Yes |
| View dashboard stats | No | Yes | Yes |

---

## Main Functionalities

- User registration and login
- HMAC-based token authentication
- Role-based access control
- Full book CRUD operations
- Book search by title, author, or ISBN
- Filtering by genre and availability
- Borrowing and returning books
- Loan tracking
- User management for admins
- Dashboard statistics
- SQLite database integration
- Layered architecture
- Frontend UI
- Automated pytest test suite

---

## Technology Stack

- **Python**
- **Flask**
- **SQLite**
- **Werkzeug password hashing**
- **pytest**
- **HTML**
- **CSS**
- **JavaScript**

---

## Project Structure

```text
library-inventory-system/
│
├── backend/
│   ├── app.py
│   ├── auth.py
│   ├── database.py
│   ├── models.py
│   ├── services.py
│   ├── __init__.py
│   │
│   ├── templates/
│   │   └── index.html
│   │
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
│
├── tests/
│   └── test_api.py
│
├── requirements.txt
├── README.md
├── .gitignore
└── library.db
```

---

## Database Design

The system uses three main tables:

### users

Stores application users and roles.

```text
id
username
password_hash
role
created_at
```

### books

Stores book inventory information.

```text
id
isbn
title
author
genre
publication_year
total_copies
available_copies
added_by
created_at
updated_at
```

### loans

Stores book borrowing records.

```text
id
book_id
user_id
loaned_at
due_date
returned_at
status
```

---

## Default Accounts

| Username | Password | Role |
|---|---|---|
| admin | admin123 | Admin |
| librarian1 | lib123 | Librarian |
| member1 | member123 | Member |

---

## Installation

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Initialize the database:

```bash
python backend/database.py
```

Run the application:

```bash
python backend/app.py
```

Open the API:

```text
http://127.0.0.1:5000/
```

Open the frontend UI:

```text
http://127.0.0.1:5000/ui
```

---

## Running Tests

Run the automated test suite:

```bash
python -m pytest tests/test_api.py -v
```

Expected result:

```text
20 passed
```

---

## API Endpoints

### Authentication

| Method | Endpoint | Access | Description |
|---|---|---|---|
| POST | `/api/auth/login` | Public | Login and receive token |
| POST | `/api/auth/register` | Public | Register a new member |

### Books

| Method | Endpoint | Access | Description |
|---|---|---|---|
| GET | `/api/books` | Public | List, search, and filter books |
| GET | `/api/books/:id` | Public | Get one book |
| POST | `/api/books` | Admin, Librarian | Add book |
| PUT | `/api/books/:id` | Admin, Librarian | Update book |
| DELETE | `/api/books/:id` | Admin | Delete book |

### Loans

| Method | Endpoint | Access | Description |
|---|---|---|---|
| POST | `/api/loans` | Logged-in users | Borrow book |
| GET | `/api/loans/mine` | Logged-in users | View own loans |
| GET | `/api/loans` | Admin, Librarian | View all loans |
| PATCH | `/api/loans/:id/return` | Admin, Librarian | Return book |

### Users

| Method | Endpoint | Access | Description |
|---|---|---|---|
| GET | `/api/users` | Admin | List users |
| GET | `/api/users/:id` | Admin | Get one user |
| PATCH | `/api/users/:id/role` | Admin | Change user role |
| DELETE | `/api/users/:id` | Admin | Delete user |

### Stats

| Method | Endpoint | Access | Description |
|---|---|---|---|
| GET | `/api/stats` | Admin, Librarian | View dashboard statistics |

---

## Example API Usage

### Login

```http
POST /api/auth/login
```

Request body:

```json
{
  "username": "admin",
  "password": "admin123"
}
```

Successful response:

```json
{
  "status": "success",
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    },
    "token": "TOKEN_HERE"
  }
}
```

### Add a Book

```http
POST /api/books
Authorization: Bearer TOKEN_HERE
Content-Type: application/json
```

Request body:

```json
{
  "isbn": "9780441172719",
  "title": "Dune",
  "author": "Frank Herbert",
  "genre": "Science Fiction",
  "publication_year": 1965,
  "total_copies": 3
}
```

### Search Books

```http
GET /api/books?search=clean&available=true
```

---

## Testing Summary

The project includes 20 automated tests covering:

- Login success
- Login failure
- User registration
- Book listing
- Book search
- Genre filtering
- Book creation
- Book update
- Book deletion
- Role permission checks
- Borrowing books
- Returning books
- Viewing loans
- Viewing users
- Changing roles
- Viewing dashboard statistics

---

## Layered Architecture

The system follows a layered architecture:

```text
Frontend UI
    ↓
Flask Routes
    ↓
Authentication and Role Middleware
    ↓
Model/Data Access Layer
    ↓
SQLite Database
```

This separation keeps the code clean, testable, and easier to maintain.

---

## Demo Flow

A recommended demo flow:

1. Open the frontend at `/ui`
2. Login as a member
3. Search and filter books
4. Borrow a book
5. View "My Loans"
6. Logout
7. Login as librarian
8. View dashboard statistics
9. Add a new book
10. View all loans
11. Return a book
12. Logout
13. Login as admin
14. Open user management
15. Change a user's role
16. Show pytest result: `20 passed`

---

## Future Improvements

Possible future improvements include:

- PostgreSQL database support
- Pagination controls in the frontend
- Overdue loan notifications
- Email reminders
- Book cover images
- Barcode/ISBN scanning
- Docker deployment
- More detailed analytics dashboard

---

## Authors

- Yasser Bouyaddid
- Karthik Reddy Chilkuri
- Syed Maghboul
