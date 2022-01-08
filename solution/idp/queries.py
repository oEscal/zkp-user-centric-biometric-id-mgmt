import sqlite3
import bcrypt
import re

DB_NAME = 'idp/idp.db'


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_user(field_content: str, field_name='username', as_dict=False) -> tuple or dict:
    regex = re.compile('[^a-zA-Z]')
    field_name = regex.sub('', field_name)

    with sqlite3.connect(DB_NAME) as con:
        if as_dict:
            con.row_factory = dict_factory
        r = con.execute(f"SELECT * FROM user WHERE {field_name}=?",
                        [field_content])

    return r.fetchone() or ({} if as_dict else [])


def save_user(username: str, password: str):
    # hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute("INSERT INTO user(username, password) values(?, ?)", (username, password))
            con.commit()

            return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def update_user(user_id, new_args):
    try:
        with sqlite3.connect(DB_NAME) as con:
            # if 'password' in new_args:
            #     new_args['password'] = bcrypt.hashpw(new_args['password'].encode(), bcrypt.gensalt())

            query = ", ".join([f'{field_name}=?' for field_name in new_args])
            values = list(new_args.values())

            con.execute(f'UPDATE USER SET {query} where id = ?', (*values, user_id))
            con.commit()

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def delete_user(user_id):
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute('DELETE FROM USER where id = ?', (user_id))
            con.commit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


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


def get_user_key(id: str, username: str) -> tuple[bytes]:
    with sqlite3.connect(DB_NAME) as con:
        r = con.execute("SELECT value, not_valid_after FROM keys WHERE id=? AND user=?", [id, username])
        return r.fetchone()


def check_credentials(username, password):
    saved_password = get_user(username, as_dict=True).get('password')
    if saved_password is None:
        return False

    return saved_password == password  # bcrypt.checkpw(password.encode(), saved_hashed_password)


def save_faces(username: str, faces: bytes) -> bool:
    print(username)
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute("UPDATE user SET faces=? WHERE username=?",
                        [faces, username])
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_faces(username) -> bytes:
    with sqlite3.connect(DB_NAME) as con:
        r = con.execute("SELECT faces FROM user WHERE username=?", [username])
        return r.fetchone()[0]


def save_fingerprint(username, model_data):
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute("UPDATE user set fingerprints=? where username=?", [model_data, username])
            con.commit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_fingerprint(username):
    try:
        with sqlite3.connect(DB_NAME) as con:
            r = con.execute("SELECT fingerprints FROM user WHERE username=?", [username])
            return r.fetchone()[0]
    except Exception as e:
        print(f"Error: {e}")
        return None


def setup_database():
    with sqlite3.connect(DB_NAME) as con:
        con.execute("CREATE TABLE if not exists user ("
                    "id integer primary key,"
                    "username text not null unique,"
                    "password blob null,"
                    "faces blob,"
                    "fingerprints blob"
                    ")")
        con.execute("CREATE TABLE if not exists keys ("
                    "id text primary key,"
                    "user text not null,"
                    "value text not null,"
                    "not_valid_after real not null,"
                    "foreign key(user) references user(id) on update cascade on delete cascade"
                    ")")
