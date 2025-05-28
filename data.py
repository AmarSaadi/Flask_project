from flask import Flask,render_template,redirect,url_for,flash,get_flashed_messages,request
from flask_sqlalchemy import SQLAlchemy
from auth_forms import LoginForm,PurchaseForm,SellForm
from flask_login import LoginManager
from flask_login import login_user,logout_user,current_user,login_required,UserMixin
from flask_bcrypt import Bcrypt

db=SQLAlchemy()
bcrypt = Bcrypt()
login_manager=LoginManager()


app=Flask(__name__,template_folder="templates")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = '0887d78ac2592a53d8926566'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message_category = 'info'
   
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  


class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=30), unique=True, nullable=False)
    email_address = db.Column(db.String(length=50), unique=True, nullable=False)
    password_hash =  db.Column(db.String(length=128), nullable=False)
    budget = db.Column(db.Integer(),nullable=False,default=1000)
    items = db.relationship('Item',backref='owner_user',lazy=True)
    @property
    def prettier_budget(self):
        if len(str(self.budget)) >= 4:
            return f'{str(self.budget)[:-3]},{str(self.budget)[-3:]}$'
        else:
            return f'{self.budget}$'
        
    @property
    def password(self):
        return self.password_hash
    @password.setter
    def password(self,plain_text):
        self.password_hash = bcrypt.generate_password_hash(plain_text).decode('utf-8')
    def check_password(self, attempt_password):
     return bcrypt.check_password_hash(self.password_hash, attempt_password)




class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(length=30),nullable=False,unique=True)
    price = db.Column(db.Integer(),nullable=False)  
    barcode = db.Column(db.String(length=12),nullable=False,unique=True)
    description = db.Column(db.String(length=1024),nullable=False,unique=True)

    owner= db.Column(db.Integer(), db.ForeignKey('user.id'))
  

    def __repr__(self):
        return f"Item('{self.name}', '{self.price}')"

from auth_forms import RegisterForm
@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')
@app.route('/data',methods=['GET', 'POST'])
@login_required
def data():
     purchase_form = PurchaseForm()
     if request.method == 'POST':
          purchased_item_name = request.form.get('purchase_item')
          item = Item.query.filter_by(name=purchased_item_name).first()
          if item:
                if current_user.budget >= item.price:
                    current_user.budget -= item.price
                    item.owner = current_user.id
                    print(f"Buying: {item.name}, setting owner to {current_user.id}")
                    print(f"[DEBUG] Purchasing item: {item.name}, setting owner to {current_user.id}")
                    db.session.commit()
                    flash(f'You purchased {item.name} for {item.price}$', category='success')
                else:
                    flash('Insufficient budget to purchase this item.', category='danger')
          else:
                 flash('Item not found.', category='danger')
          return redirect(url_for('data'))
    #  if request.method == 'GET':
    #       items= Item.query.filter_by(owner=current_user.id)
    #       print(f"Your Items: {[i.name for i in items]}")
    #       print(items)
    #       return render_template('data.html',item_name=items,purchase_form=purchase_form)
     items= Item.query.filter_by(owner=None).all()
     print(f"Market Items: {[i.name for i in items]}")
     print(items)
     return render_template('data.html',item_name=items,purchase_form=purchase_form)
          
    #  with app.app_context():   
        # print(items)

     
@app.route('/register',methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,email_address=form.email_address.data,password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f'Account created successfully! You are now logged in as: {user_to_create.username}', category='success')
        return redirect(url_for('data'))
    if form.errors !={}:
        for err_msg in form.errors.values():
            flash(f"There was an error with creating a user:{err_msg}",category="danger")

    return render_template('forms.html', form=form)
@app.route('/login',methods=['GET','POST']) 
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password(form.password.data):
            login_user(attempted_user)
            flash(f'Login successful! as: {attempted_user.username}', category='success')  
            return redirect(url_for('data'))
        else:
            flash('Invalid username or password', category='danger')  

    return render_template('login.html', form=form)
@app.route('/logout')
def logout_page():
    logout_user()
    flash('You have been logged out!', category='info')
    return redirect(url_for('home_page'))

if __name__ == '__main__':
   with app.app_context():  # Ensure the app context is available
        db.create_all()
   app.run(debug=True)
