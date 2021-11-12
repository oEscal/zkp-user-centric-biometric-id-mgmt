import sqlite3
import bcrypt

DB_NAME = 'idp/idp.db'


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_user(username: str, as_dict=False) -> tuple or dict:
    with sqlite3.connect(DB_NAME) as con:
        if as_dict:
            con.row_factory = dict_factory
        r = con.execute("SELECT password FROM user WHERE username=?",
                        [username])
        return r.fetchone()


def save_user_key(id: str, username: str, key: str, not_valid_after: float) -> bool:
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute("INSERT INTO keys(id, user, value, not_valid_after) values(?, ?, ?, ?)",
                        [id, username, key, not_valid_after])
            con.commit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_user_key(id: str, username: str) -> tuple:
    with sqlite3.connect(DB_NAME) as con:
        r = con.execute("SELECT value, not_valid_after FROM keys WHERE id=? AND user=?", [id, username])
        return r.fetchone()


def save_user(username: str, password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute("INSERT INTO user(username, password) values(?, ?)", (username, hashed))
            con.commit()

            return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def check_credentials(username, password):
    saved_hashed_password = get_user(username, as_dict=True).get('password')
    if saved_hashed_password is None:
        return False

    return bcrypt.checkpw(password.encode(), saved_hashed_password)


def setup_database():
    with sqlite3.connect(DB_NAME) as con:
        con.execute("CREATE TABLE if not exists user ("
                    "username text primary key,"
                    "password blob null"
                    ")")
        con.execute("CREATE TABLE if not exists keys ("
                    "id text primary key,"
                    "user text not null,"
                    "value text not null,"
                    "not_valid_after real not null,"
                    "foreign key(user) references user(username) on update cascade on delete cascade"
                    ")")
