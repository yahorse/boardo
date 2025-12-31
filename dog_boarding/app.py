import os
import sqlite3
import secrets
from datetime import datetime, date
from contextlib import closing
from typing import Any, Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# Config and App setup
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.environ.get("KENNEL_DB_PATH", "kennel.db")

login_manager = LoginManager(app)
login_manager.login_view = "login"

def get_db() -> sqlite3.Connection:
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def exec_sql(sql: str, args: tuple[Any, ...] = ()) -> None:
    """Execute a statement that modifies data."""
    with closing(get_db()) as conn, conn:
        conn.execute(sql, args)

def query_all(sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """Query multiple rows."""
    with closing(get_db()) as conn:
        cur = conn.execute(sql, args)
        return cur.fetchall()

def query_one(sql: str, args: tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
    """Query a single row."""
    with closing(get_db()) as conn:
        cur = conn.execute(sql, args)
        return cur.fetchone()

def init_db() -> None:
    """Create tables if they don't exist."""
    with closing(get_db()) as conn, conn:
        # Users: owners, staff, admin
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner',
                name TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        # Pets
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                breed TEXT,
                birth_date DATE,
                notes TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );
            """
        )
        # Rooms
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                room_type TEXT NOT NULL,
                capacity INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        # Bookings
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                room_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id),
                FOREIGN KEY(room_id) REFERENCES rooms(id)
            );
            """
        )
        # BookingPets (many-to-many booking <-> pets)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS booking_pets (
                booking_id INTEGER,
                pet_id INTEGER,
                PRIMARY KEY(booking_id, pet_id),
                FOREIGN KEY(booking_id) REFERENCES bookings(id),
                FOREIGN KEY(pet_id) REFERENCES pets(id)
            );
            """
        )
        # Seed some rooms if none exist
        cur = conn.execute("SELECT COUNT(*) AS c FROM rooms")
        if cur.fetchone()["c"] == 0:
            rooms = [
                ("Standard 1", "Standard", 1),
                ("Standard 2", "Standard", 2),
                ("Deluxe 1", "Deluxe", 1),
                ("Suite 1", "Suite", 2)
            ]
            conn.executemany(
                "INSERT INTO rooms(name, room_type, capacity) VALUES(?,?,?)", rooms
            )

# Initialize DB at import
init_db()

# -----------------------------------------------------------------------------
# User model for Flask-Login
# -----------------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, id: int, email: str, role: str = "owner", name: str = ""):
        self.id = id
        self.email = email
        self.role = role
        self.name = name or ""

    @staticmethod
    def from_row(row: sqlite3.Row) -> "User":
        return User(id=row["id"], email=row["email"], role=row["role"], name=row.get("name", ""))

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    row = query_one("SELECT * FROM users WHERE id=?", (user_id,))
    return User.from_row(row) if row else None

def is_staff() -> bool:
    """Return True if current user is staff or admin."""
    return current_user.is_authenticated and current_user.role in ("staff", "admin")

# -----------------------------------------------------------------------------
# Routes: Auth
# -----------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        name = request.form.get("name", "").strip()
        if not email or not password:
            flash("Email and password required.", "error")
            return render_template("register.html")
        existing = query_one("SELECT 1 FROM users WHERE email=?", (email,))
        if existing:
            flash("Email already registered.", "error")
            return render_template("register.html")
        exec_sql(
            "INSERT INTO users(email, password_hash, role, name) VALUES(?,?,?,?)",
            (email, generate_password_hash(password), "owner", name),
        )
        # auto-login new user
        row = query_one("SELECT * FROM users WHERE email=?", (email,))
        login_user(User.from_row(row))
        flash("Registration successful.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        row = query_one("SELECT * FROM users WHERE email=?", (email,))
        if row and check_password_hash(row["password_hash"], password):
            login_user(User.from_row(row))
            flash("Logged in.", "success")
            next_url = request.args.get("next") or "dashboard"
            return redirect(url_for(next_url))
        flash("Invalid credentials.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

# -----------------------------------------------------------------------------
# Owner dashboard and pet management
# -----------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    """Owner dashboard showing pets and upcoming bookings."""
    # Fetch pets of current user
    pets = query_all(
        "SELECT * FROM pets WHERE owner_id=? ORDER BY name ASC", (current_user.id,)
    )
    # Fetch upcoming bookings
    today_str = date.today().isoformat()
    bookings = query_all(
        """
        SELECT b.*, r.name AS room_name, r.room_type
          FROM bookings b
          JOIN rooms r ON r.id = b.room_id
         WHERE b.owner_id=? AND b.end_date>=?
         ORDER BY b.start_date ASC
        """,
        (current_user.id, today_str),
    )
    return render_template("dashboard.html", pets=pets, bookings=bookings)

@app.route("/pets")
@login_required
def pets():
    pets = query_all("SELECT * FROM pets WHERE owner_id=? ORDER BY name ASC", (current_user.id,))
    return render_template("pets.html", pets=pets)

@app.route("/pets/new", methods=["GET", "POST"])
@login_required
def new_pet():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        breed = request.form.get("breed", "").strip()
        birth_date = request.form.get("birth_date", "").strip()
        notes = request.form.get("notes", "").strip()
        if not name:
            flash("Pet name is required.", "error")
            return render_template("new_pet.html")
        exec_sql(
            "INSERT INTO pets(owner_id, name, breed, birth_date, notes) VALUES(?,?,?,?,?)",
            (current_user.id, name, breed or None, birth_date or None, notes),
        )
        flash("Pet added.", "success")
        return redirect(url_for("pets"))
    return render_template("new_pet.html")

# -----------------------------------------------------------------------------
# Booking
# -----------------------------------------------------------------------------
def find_available_rooms(start_date: str, end_date: str, num_pets: int) -> list[sqlite3.Row]:
    """Return rooms available for the date range and capacity."""
    # select rooms where capacity >= num_pets and not booked overlapping
    sql = """
    SELECT r.*
      FROM rooms r
     WHERE r.capacity >= ?
       AND NOT EXISTS (
           SELECT 1
             FROM bookings b
            WHERE b.room_id = r.id
              AND b.status IN ('pending','confirmed')
              AND (? < b.end_date AND ? > b.start_date)
       )
     ORDER BY r.room_type ASC, r.name ASC
    """
    return query_all(sql, (num_pets, start_date, end_date))

@app.route("/bookings/new", methods=["GET", "POST"])
@login_required
def new_booking():
    pets = query_all("SELECT * FROM pets WHERE owner_id=? ORDER BY name ASC", (current_user.id,))
    if not pets:
        flash("Add a pet before booking.", "error")
        return redirect(url_for("new_pet"))
    if request.method == "POST":
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        pet_ids = request.form.getlist("pet_ids")
        if not start_date or not end_date or not pet_ids:
            flash("Please select dates and pets.", "error")
            return render_template("new_booking.html", pets=pets, rooms=[], start_date=start_date, end_date=end_date)
        # ensure start_date < end_date
        if start_date > end_date:
            flash("End date must be after start date.", "error")
            return render_template("new_booking.html", pets=pets, rooms=[], start_date=start_date, end_date=end_date)
        num_pets = len(pet_ids)
        available_rooms = find_available_rooms(start_date, end_date, num_pets)
        if request.form.get("confirm") == "1":
            # create booking with selected room
            room_id = int(request.form.get("room_id"))
            exec_sql(
                "INSERT INTO bookings(owner_id, start_date, end_date, room_id, status) VALUES(?,?,?,?,?)",
                (current_user.id, start_date, end_date, room_id, "pending"),
            )
            booking_row = query_one("SELECT last_insert_rowid() AS id", ())
            booking_id = booking_row["id"]
            # insert booking_pets
            for pid in pet_ids:
                exec_sql(
                    "INSERT INTO booking_pets(booking_id, pet_id) VALUES(?,?)",
                    (booking_id, int(pid)),
                )
            flash("Booking created! Awaiting confirmation.", "success")
            return redirect(url_for("dashboard"))
        return render_template("new_booking.html", pets=pets, rooms=available_rooms,
                               start_date=start_date, end_date=end_date, selected_pets=pet_ids)
    # GET: show form without rooms yet
    return render_template("new_booking.html", pets=pets, rooms=[], start_date="", end_date="")

# -----------------------------------------------------------------------------
# Staff dashboard
# -----------------------------------------------------------------------------
@app.route("/staff")
@login_required
def staff_dashboard():
    if not is_staff():
        flash("Staff access only.", "error")
        return redirect(url_for("dashboard"))
    # show all bookings
    bookings = query_all(
        """
        SELECT b.*, u.email AS owner_email, r.name AS room_name
          FROM bookings b
          JOIN users u ON u.id = b.owner_id
          JOIN rooms r ON r.id = b.room_id
         ORDER BY b.start_date ASC
        """
    )
    # fetch pets per booking
    bookings_with_pets = []
    for b in bookings:
        pets_list = query_all(
            "SELECT p.name FROM booking_pets bp JOIN pets p ON p.id = bp.pet_id WHERE bp.booking_id=?",
            (b["id"],),
        )
        bookings_with_pets.append({"booking": b, "pets": [p["name"] for p in pets_list]})
    return render_template("staff_dashboard.html", bookings=bookings_with_pets)

@app.route("/staff/confirm/<int:bid>")
@login_required
def staff_confirm(bid: int):
    if not is_staff():
        flash("Staff access only.", "error")
        return redirect(url_for("dashboard"))
    exec_sql("UPDATE bookings SET status='confirmed' WHERE id=?", (bid,))
    flash("Booking confirmed.", "success")
    return redirect(url_for("staff_dashboard"))

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))
