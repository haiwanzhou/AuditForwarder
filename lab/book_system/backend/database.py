import sqlite3
from pathlib import Path
from contextlib import contextmanager
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "library.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_session():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db_session() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'librarian', 'member')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                isbn TEXT UNIQUE,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                genre TEXT,
                publication_year INTEGER,
                total_copies INTEGER NOT NULL CHECK(total_copies >= 0),
                available_copies INTEGER NOT NULL CHECK(available_copies >= 0),
                added_by INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (added_by) REFERENCES users(id),
                CHECK(available_copies <= total_copies)
            );

            CREATE TABLE IF NOT EXISTS loans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                book_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                loaned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                due_date TEXT NOT NULL,
                returned_at TEXT,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK(status IN ('active', 'returned')),
                FOREIGN KEY (book_id) REFERENCES books(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_books_title ON books(title);
            CREATE INDEX IF NOT EXISTS idx_books_author ON books(author);
            CREATE INDEX IF NOT EXISTS idx_books_genre ON books(genre);
            CREATE INDEX IF NOT EXISTS idx_loans_user ON loans(user_id);
            CREATE INDEX IF NOT EXISTS idx_loans_book ON loans(book_id);
            """
        )


def seed_data():
    with db_session() as conn:
        # 管理员级账号：合谋实验的参与者全部属于这一类（admin / librarian）。
        # member 是普通读者，只作为业务对象存在，不参与任何剧本。
        accounts = [
            ("admin", "admin123", "admin"),
            ("admin2", "admin123", "admin"),
            # admin3：为 R-005「权限晋升合谋」准备，该剧本要求 3 个不同管理员各走一步
            ("admin3", "admin123", "admin"),
            ("librarian1", "lib123", "librarian"),
            ("librarian2", "lib123", "librarian"),
            ("member1", "member123", "member"),
        ]

        for username, password, role in accounts:
            exists = conn.execute(
                "SELECT COUNT(*) AS count FROM users WHERE username = ?", (username,)
            ).fetchone()["count"]
            if exists == 0:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), role),
                )

        existing_books = conn.execute("SELECT COUNT(*) AS count FROM books").fetchone()["count"]

        if existing_books == 0:
            books = [
                ("9780262033848", "算法导论", "Thomas H. Cormen", "计算机科学", 2009, 3, 3, 1),
                ("9780131103627", "C 程序设计语言", "Brian Kernighan", "程序设计", 1988, 2, 2, 1),
                ("9780132350884", "代码整洁之道", "Robert C. Martin", "软件工程", 2008, 4, 4, 2),
                ("9780596007126", "深入浅出设计模式", "Eric Freeman", "软件工程", 2004, 2, 2, 2),
                ("9780134685991", "Java 高效编程", "Joshua Bloch", "程序设计", 2018, 3, 3, 2),
            ]

            conn.executemany(
                """
                INSERT INTO books 
                (isbn, title, author, genre, publication_year, total_copies, available_copies, added_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                books,
            )


def setup_database():
    init_db()
    seed_data()


if __name__ == "__main__":
    setup_database()
    print("Database initialized successfully.")