let token = localStorage.getItem("library_token");
let currentUser = JSON.parse(localStorage.getItem("library_user") || "null");

const loginSection = document.getElementById("loginSection");
const mainApp = document.getElementById("mainApp");
const userBox = document.getElementById("userBox");
const currentUserSpan = document.getElementById("currentUser");

function fillLogin(username, password) {
    document.getElementById("username").value = username;
    document.getElementById("password").value = password;
}

function showMessage(elementId, message, type = "success") {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = `message ${type}`;
}

async function apiRequest(url, options = {}) {
    const headers = options.headers || {};

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    if (options.body && !headers["Content-Type"]) {
        headers["Content-Type"] = "application/json";
    }

    const response = await fetch(url, {
        ...options,
        headers
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.message || "Request failed");
    }

    return data;
}

async function login() {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();

    try {
        const response = await apiRequest("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({
                username,
                password
            })
        });

        token = response.data.token;
        currentUser = response.data.user;

        localStorage.setItem("library_token", token);
        localStorage.setItem("library_user", JSON.stringify(currentUser));

        showMessage("loginMessage", "Login successful", "success");
        renderApp();

    } catch (error) {
        showMessage("loginMessage", error.message, "error");
    }
}

function logout() {
    localStorage.removeItem("library_token");
    localStorage.removeItem("library_user");

    token = null;
    currentUser = null;

    renderApp();
}

function renderApp() {
    if (!token || !currentUser) {
        loginSection.classList.remove("hidden");
        mainApp.classList.add("hidden");
        userBox.classList.add("hidden");
        return;
    }

    loginSection.classList.add("hidden");
    mainApp.classList.remove("hidden");
    userBox.classList.remove("hidden");

    currentUserSpan.textContent = `${currentUser.username} (${currentUser.role})`;

    const canManageBooks = currentUser.role === "admin" || currentUser.role === "librarian";
    const canViewAllLoans = currentUser.role === "admin" || currentUser.role === "librarian";
    const canManageUsers = currentUser.role === "admin";

    document.getElementById("addBookSection").classList.toggle("hidden", !canManageBooks);
    document.getElementById("allLoansSection").classList.toggle("hidden", !canViewAllLoans);
    document.getElementById("usersSection").classList.toggle("hidden", !canManageUsers);

    loadBooks();
    loadMyLoans();

    if (canViewAllLoans) {
        loadStats();
        loadAllLoans();
    } else {
        clearStatsForMember();
    }

    if (canManageUsers) {
        loadUsers();
    }
}

function clearStatsForMember() {
    document.getElementById("totalTitles").textContent = "-";
    document.getElementById("totalCopies").textContent = "-";
    document.getElementById("availableCopies").textContent = "-";
    document.getElementById("activeLoans").textContent = "-";
}

async function loadStats() {
    try {
        const response = await apiRequest("/api/stats");

        document.getElementById("totalTitles").textContent = response.data.total_titles;
        document.getElementById("totalCopies").textContent = response.data.total_copies;
        document.getElementById("availableCopies").textContent = response.data.available_copies;
        document.getElementById("activeLoans").textContent = response.data.active_loans;

    } catch (error) {
        console.error(error.message);
    }
}

async function loadBooks() {
    const search = document.getElementById("searchInput")?.value || "";
    const genre = document.getElementById("genreInput")?.value || "";
    const available = document.getElementById("availableInput")?.value || "";

    const params = new URLSearchParams();

    if (search) params.append("search", search);
    if (genre) params.append("genre", genre);
    if (available) params.append("available", available);

    try {
        const response = await apiRequest(`/api/books?${params.toString()}`);
        const booksTable = document.getElementById("booksTable");

        booksTable.innerHTML = "";

        response.data.books.forEach(book => {
            const canBorrow = token && book.available_copies > 0;

            booksTable.innerHTML += `
                <tr>
                    <td>${book.id}</td>
                    <td>${book.title}</td>
                    <td>${book.author}</td>
                    <td>${book.genre || "-"}</td>
                    <td>${book.total_copies}</td>
                    <td>${book.available_copies}</td>
                    <td>
                        ${canBorrow
                    ? `<button class="btn small primary" onclick="borrowBook(${book.id})">Borrow</button>`
                    : `<span class="muted">Unavailable</span>`
                }
                    </td>
                </tr>
            `;
        });

    } catch (error) {
        console.error(error.message);
    }
}

async function addBook() {
    const book = {
        isbn: document.getElementById("newIsbn").value.trim(),
        title: document.getElementById("newTitle").value.trim(),
        author: document.getElementById("newAuthor").value.trim(),
        genre: document.getElementById("newGenre").value.trim(),
        publication_year: Number(document.getElementById("newYear").value),
        total_copies: Number(document.getElementById("newCopies").value || 1)
    };

    try {
        await apiRequest("/api/books", {
            method: "POST",
            body: JSON.stringify(book)
        });

        showMessage("addBookMessage", "Book added successfully", "success");

        document.getElementById("newIsbn").value = "";
        document.getElementById("newTitle").value = "";
        document.getElementById("newAuthor").value = "";
        document.getElementById("newGenre").value = "";
        document.getElementById("newYear").value = "";
        document.getElementById("newCopies").value = "";

        loadBooks();
        loadStats();

    } catch (error) {
        showMessage("addBookMessage", error.message, "error");
    }
}

async function borrowBook(bookId) {
    try {
        await apiRequest("/api/loans", {
            method: "POST",
            body: JSON.stringify({
                book_id: bookId
            })
        });

        alert("Book borrowed successfully");

        loadBooks();
        loadMyLoans();

        if (currentUser.role === "admin" || currentUser.role === "librarian") {
            loadStats();
            loadAllLoans();
        }

    } catch (error) {
        alert(error.message);
    }
}

async function loadMyLoans() {
    try {
        const response = await apiRequest("/api/loans/mine");
        const table = document.getElementById("myLoansTable");

        table.innerHTML = "";

        response.data.loans.forEach(loan => {
            table.innerHTML += `
                <tr>
                    <td>${loan.id}</td>
                    <td>${loan.book_title}</td>
                    <td>${loan.due_date}</td>
                    <td><span class="badge ${loan.status}">${loan.status}</span></td>
                </tr>
            `;
        });

    } catch (error) {
        console.error(error.message);
    }
}

async function loadAllLoans() {
    try {
        const response = await apiRequest("/api/loans");
        const table = document.getElementById("allLoansTable");

        table.innerHTML = "";

        response.data.loans.forEach(loan => {
            table.innerHTML += `
                <tr>
                    <td>${loan.id}</td>
                    <td>${loan.username}</td>
                    <td>${loan.book_title}</td>
                    <td>${loan.due_date}</td>
                    <td><span class="badge ${loan.status}">${loan.status}</span></td>
                    <td>
                        ${loan.status === "active"
                    ? `<button class="btn small primary" onclick="returnLoan(${loan.id})">Return</button>`
                    : `<span class="muted">Done</span>`
                }
                    </td>
                </tr>
            `;
        });

    } catch (error) {
        console.error(error.message);
    }
}

async function returnLoan(loanId) {
    try {
        await apiRequest(`/api/loans/${loanId}/return`, {
            method: "PATCH"
        });

        alert("Book returned successfully");

        loadBooks();
        loadMyLoans();
        loadAllLoans();
        loadStats();

    } catch (error) {
        alert(error.message);
    }
}

async function loadUsers() {
    try {
        const response = await apiRequest("/api/users");
        const table = document.getElementById("usersTable");

        table.innerHTML = "";

        response.data.users.forEach(user => {
            table.innerHTML += `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.username}</td>
                    <td>${user.role}</td>
                    <td>
                        <select onchange="changeUserRole(${user.id}, this.value)">
                            <option value="">Select role</option>
                            <option value="member">member</option>
                            <option value="librarian">librarian</option>
                            <option value="admin">admin</option>
                        </select>
                    </td>
                </tr>
            `;
        });

    } catch (error) {
        console.error(error.message);
    }
}

async function changeUserRole(userId, role) {
    if (!role) return;

    try {
        await apiRequest(`/api/users/${userId}/role`, {
            method: "PATCH",
            body: JSON.stringify({
                role
            })
        });

        alert("User role updated successfully");
        loadUsers();

    } catch (error) {
        alert(error.message);
    }
}

renderApp();