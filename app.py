import os
from flask import Flask, render_template, url_for, request, g, session, redirect
from database import get_db
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def get_active_user():
    active_user = None

    if 'user' in session:
        user = session['user']

        db = get_db()
        user_cur = db.execute('SELECT * FROM users WHERE name = ?', [user])
        active_user = user_cur.fetchone()
    
    return active_user

@app.route('/')
def index():
    user = get_active_user()
    db = get_db()
    questions_cur = db.execute("""SELECT 
                                        questions.id as question_id, 
                                        questions.question_text, 
                                        askers.name as asker_name, 
                                        experts.name as expert_name 
                                FROM questions 
                                JOIN users as askers ON askers.id = questions.id 
                                JOIN users as experts ON questions.expert_id = experts.id 
                                WHERE questions.answer_text IS NOT NULL""")
    questions = questions_cur.fetchall()

    return render_template('home.html', user=user, questions=questions)

@app.route('/register', methods=["GET", "POST"])
def register():
    user = get_active_user()
    if request.method == "POST":
        
        db = get_db()
        existing_user_cur = db.execute('SELECT id FROM users WHERE name = ?', [request.form['name']])
        existing_user = existing_user_cur.fetchone()
        
        if existing_user:
            return render_template('register.html', user=user, error="Oopps! User already exists! Try a different username")

        hashed_password = generate_password_hash(request.form['password'], method='sha256')
        db.execute('''INSERT INTO users (name, password, expert, admin) 
                    VALUES (?, ?, ?, ?)''', [request.form['name'], hashed_password, '0', '0'])
        db.commit()

        session['user'] = request.form['name']
        return redirect(url_for('index'))

    return render_template('register.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_active_user()
    error = None
    if request.method == "POST":
        db = get_db()
        
        name = request.form['name']
        password = request.form['password']

        user_cur = db.execute('SELECT id, name, password FROM users WHERE name = ?', [name])
        user_result = user_cur.fetchone()

        if user_result:     
            if check_password_hash(user_result['password'], password):
                session['user'] = user_result['name']
                return redirect(url_for('index'))
            else:
                error = "The password is incorrect!"
        else:
            error = "The username is incorrect!"
    return render_template('login.html', user=user, error=error)

@app.route('/question/<question_id>')
def question(question_id):
    user = get_active_user()
    db = get_db()

    question_cur = db.execute('''SELECT questions.id, 
                                        questions.question_text, 
                                        questions.answer_text, 
                                        askers.name as asked_by, 
                                        experts.name as answered_by
                                FROM questions 
                                JOIN users as askers ON questions.id = askers.id
                                JOIN users as experts ON questions.expert_id = experts.expert 
                                WHERE questions.id = ?''', [question_id])
    question_view = question_cur.fetchone()

    return render_template('question.html', user=user, question=question_view)

@app.route('/answer/<question_id>', methods=["GET", "POST"])
def answer(question_id):
    user = get_active_user()
    db = get_db()

    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    if request.method == "POST":
        db.execute('UPDATE questions SET answer_text = ? WHERE id = ?', [request.form['answer'], question_id])
        db.commit()
        return redirect(url_for('unanswered'))

    question_cur = db.execute('SELECT id, question_text FROM questions where id = ?', [question_id])
    question = question_cur.fetchone()

    return render_template('answer.html', user=user, question=question)

@app.route('/ask', methods=["POST", "GET"])
def ask():
    user = get_active_user()
    db = get_db()

    if not user:
        return redirect(url_for('login'))
        
    if request.method == "POST":
        db.execute('''INSERT INTO questions (question_text, asked_by_id, expert_id) 
                    VALUES (?, ?, ?)''', [request.form['question'], user['id'], request.form['expert']])
        db.commit()

        return redirect(url_for('index'))

    expert_cur = db.execute('SELECT id, name FROM users WHERE expert = 1')
    expert_results = expert_cur.fetchall()

    return render_template('ask.html', user=user, experts=expert_results)

@app.route('/unanswered')
def unanswered():
    user = get_active_user()

    if not user:
        return redirect(url_for('login'))
        
    if user['expert'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    question_cur = db.execute('''SELECT questions.id, 
                                        question_text, 
                                        users.name 
                                FROM questions 
                                INNER JOIN users 
                                ON questions.asked_by_id = users.id 
                                WHERE questions.answer_text IS NULL and questions.expert_id = ?''', [user['id']])
    questions = question_cur.fetchall()

    return render_template('unanswered.html', user=user, questions=questions)

@app.route('/users')
def users():
    user = get_active_user()

    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    user_cur = db.execute('SELECT * FROM users')
    user_results = user_cur.fetchall()

    return render_template('users.html', user=user, users=user_results)

@app.route('/promote/<user_id>')
def promote(user_id):
    user = get_active_user

    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    db.execute('UPDATE users SET expert = 1 where id = ?', [user_id])
    db.commit()

    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)