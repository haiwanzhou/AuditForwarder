# API Documentation

## Project

**Library Inventory System**

This document describes the REST API used by the Library Inventory System. The API is built with **Flask** and uses **SQLite** for database storage.

---

## Base URL

```text
http://127.0.0.1:5000
```

---

## Response Format

Successful responses usually follow this structure:

```json
{
  "status": "success",
  "message": "success",
  "data": {}
}
```

Error responses usually follow this structure:

```json
{
  "status": "error",
  "message": "Error message here"
}
```

---

## Authentication

The API uses token-based authentication.

After login, the API returns a token. Protected endpoints require this token in the `Authorization` header.

```http
Authorization: Bearer TOKEN_HERE
```

---

# 1. Authentication Endpoints

## 1.1 Login

Authenticates a user and returns a token.

```http
POST /api/auth/login
```

### Access

Public

### Request Body

```json
{
  "username": "admin",
  "password": "admin123"
}
```

### Successful Response

```json
{
  "status": "success",
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "username": "admin",
      "role": "admin",
      "created_at": "2026-06-13 11:03:52"
    },
    "token": "TOKEN_HERE"
  }
}
```

### Error Response

```json
{
  "status": "error",
  "message": "Invalid username or password"
}
```

---

## 1.2 Register

Creates a new user account. New users are registered as `member` by default.

```http
POST /api/auth/register
```

### Access

Public

### Request Body

```json
{
  "username": "newmember",
  "password": "newpass123"
}
```

### Successful Response

```json
{
  "status": "success",
  "message": "User registered successfully",
  "data": {
    "id": 4,
    "username": "newmember",
    "role": "member",
    "created_at": "2026-06-13 11:10:00"
  }
}
```

---

# 2. Book Endpoints

## 2.1 List, Search, and Filter Books

Returns a list of books. This endpoint supports search, filtering, sorting, and pagination.

```http
GET /api/books
```

### Access

Public

### Query Parameters

| Parameter | Description | Example |
|---|---|---|
| `search` | Search by title, author, or ISBN | `/api/books?search=clean` |
| `genre` | Filter by genre | `/api/books?genre=Programming` |
| `author` | Filter by author | `/api/books?author=Martin` |
| `available` | Show only available books | `/api/books?available=true` |
| `sort` | Sort by title, author, genre, year, or newest | `/api/books?sort=title` |
| `page` | Page number | `/api/books?page=1` |
| `limit` | Number of books per page | `/api/books?limit=10` |

### Example Request

```http
GET /api/books?search=clean&available=true
```

### Successful Response

```json
{
  "status": "success",
  "message": "success",
  "data": {
    "books": [
      {
        "id": 3,
        "isbn": "9780132350884",
        "title": "Clean Code",
        "author": "Robert C. Martin",
        "genre": "Software Engineering",
        "publication_year": 2008,
        "total_copies": 4,
        "available_copies": 4,
        "added_by": 2,
        "created_at": "2026-06-13 11:03:52",
        "updated_at": "2026-06-13 11:03:52"
      }
    ],
    "page": 1,
    "limit": 10,
    "count": 1
  }
}
```

---

## 2.2 Get One Book

Returns a single book by ID.

```http
GET /api/books/{book_id}
```

### Access

Public

### Example Request

```http
GET /api/books/1
```

### Error Response

```json
{
  "status": "error",
  "message": "Book not found"
}
```

---

## 2.3 Add Book

Creates a new book.

```http
POST /api/books
```

### Access

Admin, Librarian

### Headers

```http
Authorization: Bearer TOKEN_HERE
Content-Type: application/json
```

### Request Body

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

### Successful Response

```json
{
  "status": "success",
  "message": "Book created successfully",
  "data": {
    "id": 6,
    "isbn": "9780441172719",
    "title": "Dune",
    "author": "Frank Herbert",
    "genre": "Science Fiction",
    "publication_year": 1965,
    "total_copies": 3,
    "available_copies": 3
  }
}
```

---

## 2.4 Update Book

Updates an existing book.

```http
PUT /api/books/{book_id}
```

### Access

Admin, Librarian

### Headers

```http
Authorization: Bearer TOKEN_HERE
Content-Type: application/json
```

### Request Body Example

```json
{
  "title": "Clean Code - Updated Edition",
  "total_copies": 5,
  "available_copies": 5
}
```

### Successful Response

```json
{
  "status": "success",
  "message": "Book updated successfully",
  "data": {
    "id": 3,
    "title": "Clean Code - Updated Edition"
  }
}
```

---

## 2.5 Delete Book

Deletes a book.

```http
DELETE /api/books/{book_id}
```

### Access

Admin only

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

### Business Rule

A book cannot be deleted if it has active loans.

### Successful Response

```json
{
  "status": "success",
  "message": "Book deleted successfully"
}
```

---

# 3. Loan Endpoints

## 3.1 Borrow Book

Creates a loan record and decreases the book's available copies.

```http
POST /api/loans
```

### Access

Any logged-in user

### Headers

```http
Authorization: Bearer TOKEN_HERE
Content-Type: application/json
```

### Request Body

```json
{
  "book_id": 1
}
```

Optional custom due date:

```json
{
  "book_id": 1,
  "due_date": "2026-06-30"
}
```

### Successful Response

```json
{
  "status": "success",
  "message": "Book borrowed successfully",
  "data": {
    "id": 1,
    "book_id": 1,
    "book_title": "Introduction to Algorithms",
    "user_id": 3,
    "username": "member1",
    "due_date": "2026-06-30",
    "status": "active"
  }
}
```

### Possible Error Responses

```json
{
  "status": "error",
  "message": "No available copies for this book"
}
```

```json
{
  "status": "error",
  "message": "User already has an active loan for this book"
}
```

---

## 3.2 View Own Loans

Returns the loans of the currently logged-in user.

```http
GET /api/loans/mine
```

### Access

Any logged-in user

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

### Optional Query Parameters

| Parameter | Description |
|---|---|
| `active` | If true, returns only active loans |

### Example Request

```http
GET /api/loans/mine?active=true
```

---

## 3.3 View All Loans

Returns all loans in the system.

```http
GET /api/loans
```

### Access

Admin, Librarian

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

### Optional Query Parameters

| Parameter | Description |
|---|---|
| `active` | If true, returns only active loans |

---

## 3.4 Return Book

Marks a loan as returned and increases the book's available copies.

```http
PATCH /api/loans/{loan_id}/return
```

### Access

Admin, Librarian

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

### Successful Response

```json
{
  "status": "success",
  "message": "Book returned successfully",
  "data": {
    "id": 1,
    "book_id": 1,
    "book_title": "Introduction to Algorithms",
    "user_id": 3,
    "username": "member1",
    "status": "returned"
  }
}
```

---

# 4. User Endpoints

## 4.1 List Users

Returns all users.

```http
GET /api/users
```

### Access

Admin only

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

---

## 4.2 Get One User

Returns one user by ID.

```http
GET /api/users/{user_id}
```

### Access

Admin only

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

---

## 4.3 Change User Role

Changes a user's role.

```http
PATCH /api/users/{user_id}/role
```

### Access

Admin only

### Headers

```http
Authorization: Bearer TOKEN_HERE
Content-Type: application/json
```

### Request Body

```json
{
  "role": "librarian"
}
```

### Allowed Roles

```text
admin
librarian
member
```

### Successful Response

```json
{
  "status": "success",
  "message": "User role updated successfully",
  "data": {
    "id": 3,
    "username": "member1",
    "role": "librarian"
  }
}
```

---

## 4.4 Delete User

Deletes a user.

```http
DELETE /api/users/{user_id}
```

### Access

Admin only

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

### Business Rule

A user with related loan records may not be deleted depending on database constraints.

---

# 5. Statistics Endpoint

## 5.1 Dashboard Statistics

Returns dashboard statistics.

```http
GET /api/stats
```

### Access

Admin, Librarian

### Headers

```http
Authorization: Bearer TOKEN_HERE
```

### Successful Response

```json
{
  "status": "success",
  "message": "success",
  "data": {
    "total_titles": 5,
    "total_copies": 14,
    "available_copies": 14,
    "active_loans": 0,
    "total_users": 3,
    "top_genres": [
      {
        "genre": "Programming",
        "count": 2
      },
      {
        "genre": "Software Engineering",
        "count": 2
      }
    ]
  }
}
```

---

# 6. Role-Based Access Summary

| Endpoint/Action | Member | Librarian | Admin |
|---|---:|---:|---:|
| Login/Register | Yes | Yes | Yes |
| List/search books | Yes | Yes | Yes |
| Borrow book | Yes | Yes | Yes |
| View own loans | Yes | Yes | Yes |
| Add book | No | Yes | Yes |
| Update book | No | Yes | Yes |
| Delete book | No | No | Yes |
| View all loans | No | Yes | Yes |
| Return book | No | Yes | Yes |
| View users | No | No | Yes |
| Change user roles | No | No | Yes |
| View stats | No | Yes | Yes |

---

# 7. PowerShell Testing Examples

## Login and Save Admin Token

```powershell
$loginResponse = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/auth/login" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123"}'

$TOKEN = $loginResponse.data.token
```

## View Stats

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/stats" `
  -Method GET `
  -Headers @{ Authorization = "Bearer $TOKEN" }
```

## Add Book

```powershell
$newBook = @{
  isbn = "9780441172719"
  title = "Dune"
  author = "Frank Herbert"
  genre = "Science Fiction"
  publication_year = 1965
  total_copies = 3
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/books" `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer $TOKEN" } `
  -Body $newBook
```

---

# 8. Automated Testing

Run all tests with:

```bash
python -m pytest tests/test_api.py -v
```

Expected result:

```text
20 passed
```

The test suite verifies authentication, book CRUD, search/filtering, borrowing, returning, role protection, user management, and statistics.
