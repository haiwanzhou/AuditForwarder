from werkzeug.security import generate_password_hash, check_password_hash


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


# -------------------------
# User model functions
# -------------------------

def create_user(conn, username, password, role="member"):
    password_hash = generate_password_hash(password)

    cursor = conn.execute(
        """
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        """,
        (username, password_hash, role),
    )

    return get_user_by_id(conn, cursor.lastrowid)


def get_user_by_id(conn, user_id):
    row = conn.execute(
        """
        SELECT id, username, role, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    return row_to_dict(row)


def get_user_by_username(conn, username):
    row = conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    return row_to_dict(row)


def authenticate_user(conn, username, password):
    user = get_user_by_username(conn, username)

    if user is None:
        return None

    if not check_password_hash(user["password_hash"], password):
        return None

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": user["created_at"],
    }


def list_users(conn):
    rows = conn.execute(
        """
        SELECT id, username, role, created_at
        FROM users
        ORDER BY id
        """
    ).fetchall()

    return [row_to_dict(row) for row in rows]


def update_user_role(conn, user_id, new_role):
    if new_role not in ["admin", "librarian", "member"]:
        raise ValueError("Invalid role")

    conn.execute(
        """
        UPDATE users
        SET role = ?
        WHERE id = ?
        """,
        (new_role, user_id),
    )

    return get_user_by_id(conn, user_id)


def delete_user(conn, user_id):
    user = get_user_by_id(conn, user_id)

    if user is None:
        return False

    conn.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (user_id,),
    )

    return True


# -------------------------
# Book model functions
# -------------------------

def create_book(
    conn,
    isbn,
    title,
    author,
    genre=None,
    publication_year=None,
    total_copies=1,
    added_by=None,
):
    if total_copies < 0:
        raise ValueError("Total copies cannot be negative")

    cursor = conn.execute(
        """
        INSERT INTO books
        (isbn, title, author, genre, publication_year, total_copies, available_copies, added_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            isbn,
            title,
            author,
            genre,
            publication_year,
            total_copies,
            total_copies,
            added_by,
        ),
    )

    return get_book_by_id(conn, cursor.lastrowid)


def get_book_by_id(conn, book_id):
    row = conn.execute(
        """
        SELECT *
        FROM books
        WHERE id = ?
        """,
        (book_id,),
    ).fetchone()

    return row_to_dict(row)


def list_books(
    conn,
    search=None,
    genre=None,
    author=None,
    available_only=False,
    sort_by="title",
    page=1,
    limit=10,
):
    allowed_sort_columns = {
        "title": "title",
        "author": "author",
        "genre": "genre",
        "year": "publication_year",
        "newest": "created_at",
    }

    sort_column = allowed_sort_columns.get(sort_by, "title")

    query = """
        SELECT *
        FROM books
        WHERE 1 = 1
    """

    params = []

    if search:
        query += """
            AND (
                title LIKE ?
                OR author LIKE ?
                OR isbn LIKE ?
            )
        """
        search_value = f"%{search}%"
        params.extend([search_value, search_value, search_value])

    if genre:
        query += " AND genre = ?"
        params.append(genre)

    if author:
        query += " AND author LIKE ?"
        params.append(f"%{author}%")

    if available_only:
        query += " AND available_copies > 0"

    query += f" ORDER BY {sort_column}"

    if sort_by == "newest":
        query += " DESC"

    offset = (page - 1) * limit
    query += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()

    return [row_to_dict(row) for row in rows]


def update_book(conn, book_id, data):
    book = get_book_by_id(conn, book_id)

    if book is None:
        return None

    allowed_fields = [
        "isbn",
        "title",
        "author",
        "genre",
        "publication_year",
        "total_copies",
        "available_copies",
    ]

    fields = []
    params = []

    for field in allowed_fields:
        if field in data:
            fields.append(f"{field} = ?")
            params.append(data[field])

    if not fields:
        return book

    fields.append("updated_at = CURRENT_TIMESTAMP")

    query = f"""
        UPDATE books
        SET {", ".join(fields)}
        WHERE id = ?
    """

    params.append(book_id)
    conn.execute(query, params)

    return get_book_by_id(conn, book_id)


def delete_book(conn, book_id):
    book = get_book_by_id(conn, book_id)

    if book is None:
        return False

    active_loan = conn.execute(
        """
        SELECT id
        FROM loans
        WHERE book_id = ?
        AND status = 'active'
        """,
        (book_id,),
    ).fetchone()

    if active_loan:
        raise ValueError("Cannot delete a book with active loans")

    conn.execute(
        """
        DELETE FROM books
        WHERE id = ?
        """,
        (book_id,),
    )

    return True


# -------------------------
# Loan model functions
# -------------------------

def create_loan(conn, book_id, user_id, due_date):
    book = get_book_by_id(conn, book_id)

    if book is None:
        raise ValueError("Book not found")

    if book["available_copies"] <= 0:
        raise ValueError("No available copies for this book")

    existing_active_loan = conn.execute(
        """
        SELECT id
        FROM loans
        WHERE book_id = ?
        AND user_id = ?
        AND status = 'active'
        """,
        (book_id, user_id),
    ).fetchone()

    if existing_active_loan:
        raise ValueError("User already has an active loan for this book")

    conn.execute(
        """
        UPDATE books
        SET available_copies = available_copies - 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (book_id,),
    )

    cursor = conn.execute(
        """
        INSERT INTO loans (book_id, user_id, due_date, status)
        VALUES (?, ?, ?, 'active')
        """,
        (book_id, user_id, due_date),
    )

    return get_loan_by_id(conn, cursor.lastrowid)


def get_loan_by_id(conn, loan_id):
    row = conn.execute(
        """
        SELECT
            loans.id,
            loans.book_id,
            books.title AS book_title,
            loans.user_id,
            users.username,
            loans.loaned_at,
            loans.due_date,
            loans.returned_at,
            loans.status
        FROM loans
        JOIN books ON loans.book_id = books.id
        JOIN users ON loans.user_id = users.id
        WHERE loans.id = ?
        """,
        (loan_id,),
    ).fetchone()

    return row_to_dict(row)


def list_loans(conn, user_id=None, active_only=False):
    query = """
        SELECT
            loans.id,
            loans.book_id,
            books.title AS book_title,
            loans.user_id,
            users.username,
            loans.loaned_at,
            loans.due_date,
            loans.returned_at,
            loans.status
        FROM loans
        JOIN books ON loans.book_id = books.id
        JOIN users ON loans.user_id = users.id
        WHERE 1 = 1
    """

    params = []

    if user_id:
        query += " AND loans.user_id = ?"
        params.append(user_id)

    if active_only:
        query += " AND loans.status = 'active'"

    query += " ORDER BY loans.loaned_at DESC"

    rows = conn.execute(query, params).fetchall()

    return [row_to_dict(row) for row in rows]


def return_loan(conn, loan_id):
    loan = get_loan_by_id(conn, loan_id)

    if loan is None:
        return None

    if loan["status"] == "returned":
        raise ValueError("Loan is already returned")

    conn.execute(
        """
        UPDATE loans
        SET status = 'returned',
            returned_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (loan_id,),
    )

    conn.execute(
        """
        UPDATE books
        SET available_copies = available_copies + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (loan["book_id"],),
    )

    return get_loan_by_id(conn, loan_id)


# -------------------------
# Statistics model function
# -------------------------

def get_stats(conn):
    total_titles = conn.execute(
        "SELECT COUNT(*) AS count FROM books"
    ).fetchone()["count"]

    total_copies = conn.execute(
        "SELECT COALESCE(SUM(total_copies), 0) AS count FROM books"
    ).fetchone()["count"]

    available_copies = conn.execute(
        "SELECT COALESCE(SUM(available_copies), 0) AS count FROM books"
    ).fetchone()["count"]

    active_loans = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM loans
        WHERE status = 'active'
        """
    ).fetchone()["count"]

    total_users = conn.execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()["count"]

    top_genres_rows = conn.execute(
        """
        SELECT genre, COUNT(*) AS count
        FROM books
        WHERE genre IS NOT NULL
        GROUP BY genre
        ORDER BY count DESC
        LIMIT 5
        """
    ).fetchall()

    top_genres = [row_to_dict(row) for row in top_genres_rows]

    return {
        "total_titles": total_titles,
        "total_copies": total_copies,
        "available_copies": available_copies,
        "active_loans": active_loans,
        "total_users": total_users,
        "top_genres": top_genres,
    }