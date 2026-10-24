import pytest

import backend.database as database
import backend.app as app_module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """
    Creates a fresh temporary database for each test.
    This prevents tests from modifying the real library.db file.
    """
    test_db_path = tmp_path / "test_library.db"

    monkeypatch.setattr(database, "DB_PATH", test_db_path)

    database.setup_database()

    app_module.app.config["TESTING"] = True

    with app_module.app.test_client() as test_client:
        yield test_client


def login(client, username, password):
    response = client.post(
        "/api/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    return response


def get_token(client, username="admin", password="admin123"):
    response = login(client, username, password)
    data = response.get_json()
    return data["data"]["token"]


def auth_headers(token):
    return {
        "Authorization": f"Bearer {token}"
    }


# -------------------------
# Auth tests
# -------------------------

def test_login_success(client):
    response = login(client, "admin", "admin123")
    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["user"]["username"] == "admin"
    assert data["data"]["user"]["role"] == "admin"
    assert "token" in data["data"]


def test_login_wrong_password(client):
    response = login(client, "admin", "wrongpassword")
    data = response.get_json()

    assert response.status_code == 401
    assert data["status"] == "error"
    assert data["message"] == "Invalid username or password"


def test_register_member(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "newmember",
            "password": "newpass123",
        },
    )

    data = response.get_json()

    assert response.status_code == 201
    assert data["status"] == "success"
    assert data["data"]["username"] == "newmember"
    assert data["data"]["role"] == "member"


# -------------------------
# Book tests
# -------------------------

def test_list_books(client):
    response = client.get("/api/books")
    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["count"] >= 5
    assert len(data["data"]["books"]) >= 5


def test_search_books(client):
    response = client.get("/api/books?search=clean")
    data = response.get_json()

    assert response.status_code == 200

    titles = [book["title"] for book in data["data"]["books"]]
    assert "Clean Code" in titles


def test_filter_books_by_genre(client):
    response = client.get("/api/books?genre=Programming")
    data = response.get_json()

    assert response.status_code == 200

    books = data["data"]["books"]
    assert len(books) > 0

    for book in books:
        assert book["genre"] == "Programming"


def test_admin_can_add_book(client):
    token = get_token(client, "admin", "admin123")

    response = client.post(
        "/api/books",
        headers=auth_headers(token),
        json={
            "isbn": "9780441172719",
            "title": "Dune",
            "author": "Frank Herbert",
            "genre": "Science Fiction",
            "publication_year": 1965,
            "total_copies": 3,
        },
    )

    data = response.get_json()

    assert response.status_code == 201
    assert data["status"] == "success"
    assert data["data"]["title"] == "Dune"
    assert data["data"]["available_copies"] == 3


def test_member_cannot_add_book(client):
    token = get_token(client, "member1", "member123")

    response = client.post(
        "/api/books",
        headers=auth_headers(token),
        json={
            "title": "Forbidden Book",
            "author": "Test Author",
            "total_copies": 1,
        },
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["status"] == "error"
    assert data["message"] == "Insufficient permissions"


def test_admin_can_update_book(client):
    token = get_token(client, "admin", "admin123")

    response = client.put(
        "/api/books/1",
        headers=auth_headers(token),
        json={
            "title": "Introduction to Algorithms - Updated"
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["title"] == "Introduction to Algorithms - Updated"


def test_admin_can_delete_book(client):
    token = get_token(client, "admin", "admin123")

    response = client.delete(
        "/api/books/2",
        headers=auth_headers(token),
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"

    check_response = client.get("/api/books/2")
    assert check_response.status_code == 404


# -------------------------
# Loan tests
# -------------------------

def test_member_can_borrow_book(client):
    token = get_token(client, "member1", "member123")

    response = client.post(
        "/api/loans",
        headers=auth_headers(token),
        json={
            "book_id": 1
        },
    )

    data = response.get_json()

    assert response.status_code == 201
    assert data["status"] == "success"
    assert data["data"]["book_id"] == 1
    assert data["data"]["status"] == "active"


def test_borrow_book_decreases_available_copies(client):
    token = get_token(client, "member1", "member123")

    client.post(
        "/api/loans",
        headers=auth_headers(token),
        json={
            "book_id": 1
        },
    )

    book_response = client.get("/api/books/1")
    book_data = book_response.get_json()

    assert book_response.status_code == 200
    assert book_data["data"]["available_copies"] == 2


def test_cannot_borrow_same_book_twice(client):
    token = get_token(client, "member1", "member123")

    first_response = client.post(
        "/api/loans",
        headers=auth_headers(token),
        json={
            "book_id": 1
        },
    )

    second_response = client.post(
        "/api/loans",
        headers=auth_headers(token),
        json={
            "book_id": 1
        },
    )

    second_data = second_response.get_json()

    assert first_response.status_code == 201
    assert second_response.status_code == 400
    assert second_data["message"] == "User already has an active loan for this book"


def test_member_can_view_own_loans(client):
    token = get_token(client, "member1", "member123")

    client.post(
        "/api/loans",
        headers=auth_headers(token),
        json={
            "book_id": 1
        },
    )

    response = client.get(
        "/api/loans/mine",
        headers=auth_headers(token),
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["count"] == 1


def test_librarian_can_view_all_loans(client):
    member_token = get_token(client, "member1", "member123")

    client.post(
        "/api/loans",
        headers=auth_headers(member_token),
        json={
            "book_id": 1
        },
    )

    librarian_token = get_token(client, "librarian1", "lib123")

    response = client.get(
        "/api/loans",
        headers=auth_headers(librarian_token),
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["count"] == 1


def test_librarian_can_return_book(client):
    member_token = get_token(client, "member1", "member123")

    borrow_response = client.post(
        "/api/loans",
        headers=auth_headers(member_token),
        json={
            "book_id": 1
        },
    )

    borrow_data = borrow_response.get_json()
    loan_id = borrow_data["data"]["id"]

    librarian_token = get_token(client, "librarian1", "lib123")

    return_response = client.patch(
        f"/api/loans/{loan_id}/return",
        headers=auth_headers(librarian_token),
    )

    return_data = return_response.get_json()

    assert return_response.status_code == 200
    assert return_data["status"] == "success"
    assert return_data["data"]["status"] == "returned"

    book_response = client.get("/api/books/1")
    book_data = book_response.get_json()

    assert book_data["data"]["available_copies"] == 3


# -------------------------
# User and stats tests
# -------------------------

def test_admin_can_view_users(client):
    token = get_token(client, "admin", "admin123")

    response = client.get(
        "/api/users",
        headers=auth_headers(token),
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["count"] == 3


def test_admin_can_change_user_role(client):
    token = get_token(client, "admin", "admin123")

    response = client.patch(
        "/api/users/3/role",
        headers=auth_headers(token),
        json={
            "role": "librarian"
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["role"] == "librarian"


def test_member_cannot_view_users(client):
    token = get_token(client, "member1", "member123")

    response = client.get(
        "/api/users",
        headers=auth_headers(token),
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["status"] == "error"
    assert data["message"] == "Insufficient permissions"


def test_admin_can_view_stats(client):
    token = get_token(client, "admin", "admin123")

    response = client.get(
        "/api/stats",
        headers=auth_headers(token),
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "success"
    assert data["data"]["total_titles"] == 5
    assert data["data"]["total_users"] == 3
    assert "top_genres" in data["data"]