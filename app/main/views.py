from flask import render_template
from . import main


@main.route('/')
def index():
    return render_template('index.html')

# @main.route('/users', methods=['GET', 'POST'])
# def users():
#     conn = get_connection()
#     with conn:
#         with conn.cursor() as cur:
#             cur.execute("SELECT * FROM users")
#             users = cur.fetchall()
#             release_connection(conn)
#     return render_template("users/users.html", users=users)


# @main.route('/create_user', methods=['GET', 'POST'])
# def users():
#     conn = get_connection()
#     with conn:
#         with conn.cursor() as cur:
#             cur.execute("SELECT * FROM users")
#             users = cur.fetchall()
#             release_connection(conn)
#     return render_template("users/create_user.html", user=user)