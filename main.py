import os
from io import BytesIO
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from flask import Flask, request, render_template, flash, redirect, url_for, session, jsonify, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS  # Import the CORS extension
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
from flask import session
from datetime import datetime , timedelta
import logging
from sqlalchemy import func
from flask import request, render_template
from sqlalchemy import func, desc, asc

port = int(os.environ.get('PORT', 5000))

app = Flask(__name__,
            template_folder="templates",
            static_url_path="/static")
# Setting up CORS to handle headers for all responses
CORS(app)
# Create a CSRF protected form to use the CSRF token
#csrf = CSRFProtect(app)
#Setting our secret key.
app.config['SECRET_KEY'] = 'Hari_3862'

# Configure Flask-Session to use filesystem-based session storage
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize the session
Session(app)
#Inititalizing the SQLLite Engine.
database_path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                             'mad1-library.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grocery_store_database.db'

db = SQLAlchemy(app)

#We use the LoginManager in our app for handling user authentication and user session management.
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'

class books(db.Model):
    __tablename__ = 'books'
    book_id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    book_name = db.Column(db.Text, unique=True, nullable=False)
    author = db.Column(db.Text, nullable=False)
    section = db.Column(db.Text, nullable=False)  # Changed from BLOB to Text for ease of use with SQLAlchemy
    price = db.Column(db.Numeric, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    popularity = db.Column(db.Integer, nullable=False)
    author_id = db.Column(db.Integer, nullable=False)

class authors(db.Model):
  _tablename_ = 'authors'
  id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False, autoincrement=True)
  name = db.Column(db.Text, unique=True, nullable=False)

class Sections(db.Model):
    __tablename__ = 'sections'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    section_name = db.Column(db.Text)

class borrowed_books(db.Model):
    __tablename__ = 'borrowed_books'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    book_id = db.Column(db.Integer, db.ForeignKey('books.book_id'))
    borrowed_date = db.Column(db.DateTime, default=datetime.utcnow)
    access_end_date = db.Column(db.DateTime)
    approval_status = db.Column(db.Boolean, default=False)

class past_orders(db.Model):
    __tablename__ = 'past_orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.book_id'), nullable=False)
    borrowed_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    access_end_date = db.Column(db.DateTime, nullable=True)

class BookRating(db.Model):
    __tablename__ = 'book_rating'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.book_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=True)

class Users(UserMixin, db.Model):
  id = db.Column(db.Integer,
                       primary_key=True,
                       autoincrement=True,
                       nullable=False)
  username = db.Column(db.String(50), unique=True, nullable=False)
  email = db.Column(db.String(100), unique=True, nullable=False)
  password = db.Column(
    db.String(128),
    nullable=False)  # Use 128 characters for the hashed password
  user_type = db.Column(db.String(20), nullable=False)

    # def __repr__(self):
    #     return f'<User {self.name}>'
  def generate_hashed_password(self, password):
    self.Hashed_Password = generate_password_hash(password)

  def check_password_existence(self, password):
    return check_password_hash(self.Hashed_Password, password)

  def is_active(self):
    #We assume all users are active.
    return True

  # Required by Flask-Login to get a unique identifier for the user.
  def get_id(self):
    return str(self.id)
class UserBalance(db.Model):
    __tablename__ = 'user_balance'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True, nullable=False)
    balance = db.Column(db.Numeric, nullable=False)

    def __init__(self, user_id, balance):
        self.user_id = user_id
        self.balance = balance

    def __repr__(self):
        return '<UserBalance user_id={user_id} balance={balance}>'.format(user_id=self.user_id, balance=self.balance)


#This is used to retrieve a user object based on the user ID stored in the session. and this returns None if the User is not found.
@login_manager.user_loader
def Load_User(user_ID):
  return Users.query.get(int(user_ID))


def get_current_user():
  return current_user


@app.route('/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        user_type = request.form.get('role')

        # Check if user already exists
        user_exists = Users.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already in use. Please choose another one.')
            return redirect(url_for('signup'))

        # Hash the user's password for security
        hashed_password = generate_password_hash(password)

        # Create new user and add to database
        new_user = Users(username=name, email=email, password=hashed_password, user_type=user_type)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful!')
        return redirect(url_for('login'))  # Assuming you have a login route
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Users.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['current_user_id'] = user.id  # Storing the user_id in session
            if user.user_type == 'admin':
                return redirect(url_for('admin_home'))
            else:
                return redirect(url_for('user_home'))
        else:
            flash('Invalid login credentials!')

    return render_template('login.html')

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if request.method == 'POST':
        # Use .get() to avoid KeyError if 'author_select' is not submitted
        # Fallback to None if 'author_select' or 'author' keys are not present
        author_name_select = request.form.get('author_select', None)
        author_name_input = request.form.get('author', '').strip()  # Trim whitespace from 'author' input

        # Decide which author name to use; prioritize input field if provided
        author_name = author_name_input if author_name_input else author_name_select

        section = request.form['section']

        # Proceed with the rest of the logic
        author = authors.query.filter_by(name=author_name).first()
        if not author and author_name:
            author = authors(name=author_name)
            db.session.add(author)
            db.session.flush()  # Assign an ID without committing yet
        
        if author:
            new_book = books(
                book_name=request.form['book_name'],
                author=author_name,
                section=section,
                price=request.form['price'],
                rating=0,
                popularity=0,
                author_id=author.id
            )
            db.session.add(new_book)
            db.session.commit()
            return redirect(url_for('admin_home'))
    else:
        sections = Sections.query.all()
        authors_list = authors.query.all()
        return render_template('add_book.html', sections=sections, authors=authors_list)


@app.route('/admin_home')
def admin_home():
    all_sections = Sections.query.all()
    section_books = {}
    for section in all_sections:
        section_books[section.section_name] = books.query.filter_by(section=section.section_name).all()

    borrowed_books_list = borrowed_books.query.join(books).join(Users).add_columns(Users.id, Users.username, books.book_name, books.book_id, borrowed_books.borrowed_date, borrowed_books.access_end_date, borrowed_books.approval_status).all()

    borrowed = [b for b in borrowed_books_list if b.approval_status]
    to_be_approved = [b for b in borrowed_books_list if not b.approval_status]
    return render_template('admin_home.html', section_books=section_books, borrowed=borrowed, to_be_approved=to_be_approved)


@app.route('/admin_home/approve', methods=['POST'])
def approve_book():
    book_id = request.form.get('book_id')
    user_id = request.form.get('user_id')
    #print(f'{book_id},{user_id}')
    book = borrowed_books.query.filter_by(user_id=user_id, book_id=book_id).first()
    #print(book)
    if book:
        book.approval_status = True
        db.session.commit()
    return redirect(url_for('admin_home'))

@app.route('/admin_home/deny', methods=['POST'])
def deny_book():
    book_id = request.form.get('book_id')
    user_id = request.form.get('user_id')
    book = borrowed_books.query.filter_by(user_id=user_id, book_id=book_id).first()
    if book:
        db.session.delete(book)
        db.session.commit()
    return redirect(url_for('admin_home'))

@app.route('/admin_home/revoke', methods=['POST'])
def revoke_access():
    book_id = request.form.get('book_id')
    user_id = request.form.get('user_id')
    book = borrowed_books.query.filter_by(user_id=user_id, book_id=book_id).first()
    if book:
        new_past_order = past_orders(user_id=user_id, book_id=book_id, borrowed_date=book.borrowed_date, access_end_date=book.access_end_date)
        db.session.add(new_past_order)
        db.session.delete(book)
        db.session.commit()
    return redirect(url_for('admin_home'))

# Route to update a book's section
@app.route('/update_book/<int:book_id>', methods=['GET', 'POST'])
def update_book(book_id):
    book = books.query.get_or_404(book_id)
    if request.method == 'POST':
        book.book_name = request.form.get('book_name', book.book_name)
        book.author = request.form.get('author', book.author)
        book.section = request.form.get('section', book.section)
        book.price = request.form.get('price', book.price)
        
        db.session.commit()
        return redirect(url_for('admin_home'))
    else:
        sections = Sections.query.all()
        return render_template('update_book.html', book=book, sections=sections)


# Route to delete a book
@app.route('/delete_book/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    book = books.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('admin_home'))

@app.route('/update_section/<section_name>', methods=['GET', 'POST'])
def update_section(section_name):
    section = Sections.query.filter_by(section_name=section_name).first_or_404()
    if request.method == 'POST':
        new_section_name = request.form.get('section_name')
        
        # Check if the section name has actually been changed
        if new_section_name and new_section_name != section.section_name:
            # Find all books in the old section
            books_to_update = books.query.filter_by(section=section.section_name).all()
            # Update the section name in all found books
            for book in books_to_update:
                book.section = new_section_name
            # Update the section name in the Sections table
            section.section_name = new_section_name
            
            # Commit the changes to the database
            db.session.commit()
            
        return redirect(url_for('admin_home'))
    
    return render_template('update_section.html', section=section)


@app.route('/delete_section/<path:section_name>', methods=['POST'])
def delete_section(section_name):
    # Decode URL-encoded section name if needed (Flask should do this automatically)
    section = Sections.query.filter_by(section_name=section_name).first_or_404()
    
    books_in_section = books.query.filter_by(section=section.section_name).all()
    for book in books_in_section:
        db.session.delete(book)
    
    db.session.delete(section)
    db.session.commit()
    
    return redirect(url_for('admin_home'))


@app.route('/add_section', methods=['GET', 'POST'])
def add_section():
    if request.method == 'POST':
        new_section_name = request.form['section_name']
        # Check if the section already exists to avoid duplicates
        existing_section = Sections.query.filter_by(section_name=new_section_name).first()
        if not existing_section:
            new_section = Sections(section_name=new_section_name)
            db.session.add(new_section)
            db.session.commit()
            return redirect(url_for('admin_home'))
        else:
            # Handle the case where the section already exists
            flash('Section already exists!', 'error')
    return render_template('add_section.html')


# @app.route('/user_home_1')
# def index():
#     sort_type = request.args.get('sort', 'name_asc')  # Default sorting
#     search_query = request.args.get('search', None)  # Search query

#     if search_query:
#         # If there's a search query, filter books accordingly
#         all_books = books.query.filter((books.book_name.ilike(f'%{search_query}%')) | (books.author.ilike(f'%{search_query}%')))
#     else:
#         # If no search query, fetch all books
#         all_books = books.query

#     # Apply sorting to the filtered or complete list of books
#     if sort_type == 'rating_desc':
#         all_books = all_books.order_by(desc(func.avg(BookRating.rating)), desc(func.count(BookRating.rating)))
#     elif sort_type == 'popularity_desc':
#         all_books = all_books.order_by(desc(func.count(borrowed_books.id) + func.count(past_orders.id)))
#     elif sort_type == 'price_asc':
#         all_books = all_books.order_by(books.price.asc())
#     else:
#         all_books = all_books.order_by(books.book_name.asc())

#     # Calculate ratings and popularity
#     books_data = []
#     for book in all_books:
#         # Calculate average rating and rating count
#         rating_info = db.session.query(
#             func.avg(BookRating.rating).label('average_rating'),
#             func.count(BookRating.rating).label('rating_count')
#         ).filter(BookRating.book_id == book.book_id).one()

#         if rating_info.rating_count > 0:
#             book.avg_rating = round(rating_info.average_rating, 1)
#             book.rating_count = rating_info.rating_count
#         else:
#             book.avg_rating = book.rating
#             book.rating_count = 0

#         # Calculate popularity
#         borrowed_count = db.session.query(func.count(borrowed_books.id)).filter(borrowed_books.book_id == book.book_id).scalar()
#         orders_count = db.session.query(func.count(past_orders.id)).filter(past_orders.book_id == book.book_id).scalar()
#         book.popularity = borrowed_count + orders_count

#         books_data.append(book)

#     return render_template('user_home_1.html', all_books=books_data)

@app.route('/user_home_1')
def index():
    sort_type = request.args.get('sort', 'name_asc')  # Default sorting
    search_query = request.args.get('search', None)  # Search query

    if search_query:
        all_books = books.query.filter((books.book_name.ilike(f'%{search_query}%')) | (books.author.ilike(f'%{search_query}%')))
    else:
        all_books = books.query

    # Convert query to list to operate in Python
    all_books = all_books.all()

    # Enrich each book with ratings and popularity
    for book in all_books:
        rating_info = db.session.query(
            func.avg(BookRating.rating).label('average_rating'),
            func.count(BookRating.rating).label('rating_count')
        ).filter(BookRating.book_id == book.book_id).one()

        if rating_info.rating_count > 0:
            book.avg_rating = round(rating_info.average_rating, 1)
            book.rating_count = rating_info.rating_count
        else:
            book.avg_rating = book.rating  
            book.rating_count = 0

        borrowed_count = db.session.query(func.count(borrowed_books.id)).filter(borrowed_books.book_id == book.book_id).scalar()
        orders_count = db.session.query(func.count(past_orders.id)).filter(past_orders.book_id == book.book_id).scalar()
        book.popularity = borrowed_count + orders_count

    # Sorting books based on sort_type after enriching data
    if sort_type == 'rating_desc':
        all_books.sort(key=lambda x: (-x.avg_rating, -x.rating_count))
    elif sort_type == 'popularity_desc':
        all_books.sort(key=lambda x: -x.popularity)
    elif sort_type == 'price_asc':
        all_books.sort(key=lambda x: x.price)
    else:
        all_books.sort(key=lambda x: x.book_name.lower())  # default sort by book name

    return render_template('user_home_1.html', all_books=all_books)

@app.route('/search', methods=['GET'])
def search_books():
    keyword = request.args.get('search')
    print(keyword)
    search_results = []
    if keyword:
        # Perform a case-insensitive search on book names and authors
        raw_search_results = books.query.filter((books.book_name.ilike(f'%{keyword}%')) | (books.author.ilike(f'%{keyword}%'))).all()
    else:
        # If no keyword is provided, return all books
        raw_search_results = books.query.all()
    
    for book in raw_search_results:
        # Calculate average rating and rating count
        rating_info = db.session.query(func.avg(BookRating.rating).label('average_rating'),
                                       func.count(BookRating.rating).label('rating_count')) \
            .filter(BookRating.book_id == book.book_id) \
            .one()

        if rating_info.rating_count > 0:
            book.avg_rating = round(rating_info.average_rating, 1)
            book.rating_count = rating_info.rating_count
        else:
            book.avg_rating = book.rating
            book.rating_count = 0

        # Calculate popularity
        borrowed_count = db.session.query(func.count(borrowed_books.id)) \
            .filter(borrowed_books.book_id == book.book_id) \
            .scalar()
        orders_count = db.session.query(func.count(past_orders.id)) \
            .filter(past_orders.book_id == book.book_id) \
            .scalar()

        book.popularity = borrowed_count + orders_count
        search_results.append(book)

    print(search_results)
    return render_template('user_home_1.html', all_books=search_results)


@app.route('/user_home')
def user_home():
    filter_type = request.args.get('filter', 'author')

    if filter_type == 'author':
        filter_name = "Author"
        authors_list = authors.query.all()
        filter_groups = []
        for author in authors_list:
            author_books = books.query.filter_by(author_id=author.id).all()
            filter_groups.append({'name': author.name, 'books': author_books})
    else:  # 'section' filter
        filter_name = "section"
        sections = set(book.section for book in books.query.all())
        filter_groups = []

        for section in sections:
            section_books = books.query.filter_by(section=section).all()
            # Enrich books with author names
            for book in section_books:
                book_author = authors.query.filter_by(id=book.author_id).first()
                book.author_name = book_author.name if book_author else "Unknown Author"
            filter_groups.append({'name': section, 'books': section_books})

    for group in filter_groups:
        for book in group['books']:
            # Query to get average rating and count of ratings
            rating_info = db.session.query(func.avg(BookRating.rating).label('average_rating'),
                                           func.count(BookRating.rating).label('rating_count')) \
                .filter(BookRating.book_id == book.book_id) \
                .one()

            if rating_info.rating_count > 0:
                # If there are ratings, use the average and count
                book.avg_rating = round(rating_info.average_rating, 1)
                book.rating_count = rating_info.rating_count
            else:
                # If there are no ratings, use the book's own rating and assume 0 count
                book.avg_rating = book.rating
                book.rating_count = 0
            borrowed_count = db.session.query(func.count(borrowed_books.id)) \
                .filter(borrowed_books.book_id == book.book_id) \
                .scalar()
            orders_count = db.session.query(func.count(past_orders.id)) \
                .filter(past_orders.book_id == book.book_id) \
                .scalar()

            book.popularity = borrowed_count + orders_count
    return render_template('user_home.html', filter_name=filter_name, filter_groups=filter_groups)


@app.route('/borrow_book/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
    user_id = session.get('current_user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    # Check user's balance first
    user_balance = UserBalance.query.filter_by(user_id=user_id).first()
    if user_balance and user_balance.balance < 0:
        return jsonify({'error': 'Your account balance is negative. You cannot borrow more books until it is settled.'}), 403

    # Check if the user has already borrowed this book
    existing_borrow = borrowed_books.query.filter_by(user_id=user_id, book_id=book_id).first()
    if existing_borrow:
        return jsonify({'error': 'You have already borrowed this book'}), 400

    # Check if the user has borrowed 5 or more books
    count_borrowed_books = borrowed_books.query.filter_by(user_id=user_id).count()
    if count_borrowed_books >= 5:
        return jsonify({'error': 'You have already borrowed the maximum number of books'}), 400

    data = request.get_json()
    days = data.get('days')

    if days is None or not str(days).isdigit():
        return jsonify({'error': 'Invalid number of days provided'}), 400
    days = int(days)

    borrowed_date = datetime.utcnow()
    access_end_date = borrowed_date + timedelta(days=days)

    new_borrow = borrowed_books(user_id=user_id, book_id=book_id,
                                borrowed_date=borrowed_date,
                                access_end_date=access_end_date)
    db.session.add(new_borrow)
    db.session.commit()

    return jsonify({'message': 'Book borrowed successfully!'}), 200

@app.route('/borrowed_books', methods=['GET'])
def borrowed_book_section():
    user_id = session.get('current_user_id')
    
    existing_balance_record = UserBalance.query.filter_by(user_id=user_id).first()
    existing_balance = existing_balance_record.balance if existing_balance_record else 0

    today = datetime.utcnow().date()  # Ensure comparison with date objects
    user_borrowed_books = borrowed_books.query \
        .filter_by(user_id=user_id) \
        .join(books, borrowed_books.book_id == books.book_id) \
        .add_columns(
            borrowed_books.book_id,
            books.book_name,
            borrowed_books.borrowed_date,
            borrowed_books.access_end_date,
            borrowed_books.approval_status,
            books.price,
            func.julianday(func.date('now')) - func.julianday(borrowed_books.borrowed_date)
        ).all()

    approved_books = []
    waiting_approval_books = []
    total_current_order_value = 0

    for book in user_borrowed_books:
        # Calculate days since borrowed if access_end_date is None or in the future
        days_since_borrowed = (today - book.borrowed_date.date()).days
        current_order_value = days_since_borrowed * book.price if book.price and days_since_borrowed > 0 else 0

        book_data = {
            'book_id': book.book_id,
            'book_name': book.book_name,
            'borrowed_date': book.borrowed_date,
            'access_end_date': book.access_end_date,
            'current_order_value': current_order_value
        }

        if book.approval_status:
            approved_books.append(book_data)
            total_current_order_value += current_order_value
        else:
            waiting_approval_books.append(book_data)

    actual_balance = existing_balance - total_current_order_value

    return render_template('borrowed_books.html', approved_books=approved_books, waiting_approval_books=waiting_approval_books, existing_balance=existing_balance, total_current_order_value=total_current_order_value, actual_balance=actual_balance)

@app.route('/extend_access/<int:book_id>', methods=['POST'])
def extend_access(book_id):
    data = request.get_json()
    days = int(data.get('days', 0))
    
    
    book_to_extend = borrowed_books.query.filter_by(book_id=book_id).first()
    
    if book_to_extend:
        book_to_extend.access_end_date += timedelta(days=days)
        db.session.commit()
        return jsonify({'message': 'Access extended successfully!'})
    else:
        return jsonify({'message': 'Book not found.'}), 404

@app.route('/return_book/<int:book_id>', methods=['POST'])
def return_book(book_id):
    # Fetch the borrowed book
    borrowed_book = borrowed_books.query.filter_by(book_id=book_id).first()
    
    if borrowed_book:
        # Create a new PastOrder instance with the details from borrowed_book
        past_order = past_orders(
            user_id=borrowed_book.user_id,
            book_id=borrowed_book.book_id,
            borrowed_date=borrowed_book.borrowed_date,
            access_end_date=datetime.now()
        )
        db.session.add(past_order)
        
        # Remove the book from borrowed_books
        db.session.delete(borrowed_book)
        db.session.commit()
        
        # Redirect or return a success response
        return redirect(url_for('borrowed_book_section'))
    else:
        # Handle the case where the book is not found
        return "Book not found", 404

@app.route('/past_orders', methods=['GET'])
def past_order():
    user_id = session.get('current_user_id')
    # Update the query to include ratings and calculate order prices
    user_past_orders = db.session.query(
            past_orders.book_id,
            books.book_name,
            past_orders.borrowed_date,
            past_orders.access_end_date,
            books.price,
            (func.julianday(past_orders.access_end_date) - func.julianday(past_orders.borrowed_date)).label('days'),
            ((func.julianday(past_orders.access_end_date) - func.julianday(past_orders.borrowed_date)) * books.price).label('order_price'),
            BookRating.rating
        ) \
        .join(books, past_orders.book_id == books.book_id) \
        .outerjoin(BookRating, (BookRating.book_id == past_orders.book_id) & (BookRating.user_id == user_id)) \
        .filter(past_orders.user_id == user_id) \
        .all()

    # Calculate total spent and remaining balance
    total_spent = sum(order.order_price for order in user_past_orders if order.order_price is not None)
    remaining_balance = 2500 - total_spent  # Assuming the initial balance is 1000

    # Prepare orders with ratings for the template
    # Ensure each order has a rating attribute, even if it's None
    prepared_orders = []
    for order in user_past_orders:
        if not hasattr(order, 'rating'):
            order = order + (None,)  # Append None for missing ratings
        prepared_orders.append(order)
    # Check for an existing user balance record
    user_balance_record = UserBalance.query.filter_by(user_id=user_id).first()
    
    if user_balance_record:
        # Update the existing record
        user_balance_record.balance = remaining_balance
    else:
        # Create a new record if one doesn't exist
        new_balance_record = UserBalance(user_id=user_id, balance=remaining_balance)
        db.session.add(new_balance_record)
    
    # Commit the session to save changes to the database
    db.session.commit()
    return render_template('past_orders.html', past_orders=prepared_orders, remaining_balance=remaining_balance)

@app.route('/rate_book', methods=['POST'])
def rate_book():
    user_id = session.get('current_user_id')
    book_id = request.form.get('book_id')
    rating = request.form.get('rating')

    if not rating:
        flash('Please select a rating.')
        return redirect(url_for('past_order'))

    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            flash('Rating must be between 1 and 5.')
            return redirect(url_for('past_order'))
    except ValueError:
        flash('Invalid rating.')
        return redirect(url_for('past_order'))

    # Check if the rating already exists
    existing_rating = BookRating.query.filter_by(user_id=user_id, book_id=book_id).first()
    if existing_rating:
        existing_rating.rating = rating
        flash('Your rating has been updated.')
    else:
        new_rating = BookRating(user_id=user_id, book_id=book_id, rating=rating)
        db.session.add(new_rating)
        flash('Thank you for rating this book.')

    db.session.commit()

    return redirect(url_for('past_order'))
@app.route('/statistics')
def statistics():
    # Assuming 'db' is your database connection object
    # Query 1: Section-wise borrowed books count
    section_counts = db.session.query(Sections.section_name, db.func.count(borrowed_books.id)).join(books, books.section==Sections.section_name).join(borrowed_books, borrowed_books.book_id==books.book_id).group_by(Sections.section_name).all()

    # Query 2: Top 5 authors by borrowed books
    author_counts = db.session.query(authors.name, db.func.count(borrowed_books.id)).join(books, books.author_id==authors.id).join(borrowed_books, borrowed_books.book_id==books.book_id).group_by(authors.name).order_by(db.func.count(borrowed_books.id).desc()).limit(5).all()
    user_spend = db.session.query(Users.username, db.func.sum(2500-UserBalance.balance)).join(UserBalance, Users.id == UserBalance.user_id).group_by(Users.username).order_by(db.func.sum(2500-UserBalance.balance).desc()).limit(5).all()
    # Generate plots (will be defined in the next steps)
    section_plot_path = generate_section_plot(section_counts)
    author_plot_path = generate_author_plot(author_counts)
    user_plot_path = generate_user_plot(user_spend)
    # Render the template and pass the paths of the generated plots
    return render_template('statistics.html', section_plot=section_plot_path, author_plot=author_plot_path, user_plot=user_plot_path)
def ensure_directory_exists(path):
    os.makedirs(path, exist_ok=True)

def generate_section_plot(data):
    images_dir = 'static/images'
    ensure_directory_exists(images_dir)
    sections, counts = zip(*data)
    plt.figure(figsize=(10, 6))
    plt.pie(counts, labels=sections, autopct='%1.1f%%', startangle=140, colors=plt.cm.tab20.colors)
    plt.title('Number of Borrowed Books Section-wise')
    plt.axis('equal')
    # plt.tight_layout()
    plot_path = 'static/images/section_plot.png'
    plt.savefig(plot_path)
    plt.close()  # Close the plot to free memory
    return plot_path

def generate_author_plot(data):
    images_dir = 'static/images'
    ensure_directory_exists(images_dir)
    authors, counts = zip(*data)
    plt.figure(figsize=(10, 6))
    plt.bar(authors, counts, color='lightgreen')
    plt.title('Top 5 Authors by Borrowed Books')
    plt.xlabel('Author')
    plt.ylabel('Number of Borrowed Books')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plot_path = 'static/images/author_plot.png'
    plt.savefig(plot_path)
    plt.close()  # Close the plot to free memory
    return plot_path

def generate_user_plot(data):
    images_dir = 'static/images'
    ensure_directory_exists(images_dir)
    authors, counts = zip(*data)
    plt.figure(figsize=(10, 6))
    plt.bar(authors, counts, color='orange')
    plt.title('Top 5 Users by Amount Spent')
    plt.xlabel('User')
    plt.ylabel('Amount Spent (in ₹)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plot_path = 'static/images/user_plot.png'
    plt.savefig(plot_path)
    plt.close()  # Close the plot to free memory
    return plot_path

if __name__ == '__main__':
    app.run(debug=True)
