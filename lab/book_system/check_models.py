from backend.database import db_session
from backend.models import list_books, get_stats, authenticate_user


with db_session() as conn:
    books = list_books(conn)

    print("Books:")
    for book in books:
        print(book["id"], book["title"], "-", book["author"])

    print("\nStats:")
    print(get_stats(conn))

    print("\nLogin test:")
    print(authenticate_user(conn, "admin", "admin123"))