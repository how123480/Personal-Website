from flask import Flask, flash, redirect,request,url_for,render_template,current_app,make_response,session,g
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_paginate import Pagination, get_page_args
from werkzeug.utils import secure_filename
import os
import re
import time
import html
from datetime import timedelta
from PIL import Image

#self implement
from user import User
from models import db
from config import POSTGRES

UPLOAD_FOLDER = './static/img'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(password)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['DEBUG'] = True
#sessionID
app.secret_key = os.urandom(24)
db.init_app(app)
login_manager = LoginManager(app)

def XSSsanitize(raw_string):
	#1. filter out something wired
	# do nothing now
	#raw_string = raw_string.replace("\'", "&#39;")
	raw_string = html.escape(raw_string)
	raw_string = raw_string.replace("%", "%%")
	return raw_string

def sanitize(raw_string):
	#left only numerical and alphabet
	return re.sub("[^0-9a-z]","",raw_string)

def allowed_file(filename):
	return '.' in filename and filename.split('.')[-1].lower() in ALLOWED_EXTENSIONS

def is_account_exist(account):
	sql_cmd = """
		select user_id from user_tbl where username='{}';
	""".format(account)

	if(db.engine.execute(sql_cmd).rowcount == 0): #no record match!
		return False
	else:
		return True 

def create_user(username,password):
	sql_cmd = """
		INSERT INTO USER_TBL
		(username, password)
		VALUES ('{}','{}');
	""".format(username,password)

	db.engine.execute(sql_cmd)

	return

def is_pw_correct(username,password):
	if(is_account_exist(username)):
		sql_cmd = """
			select password from user_tbl where username='{}';
		""".format(username)

		result = db.engine.execute(sql_cmd)
		if(password == result.fetchone()['password']):
			return True
		else:
			return False

	return False

def get_login_time():
	username = current_user.get_id()
	sql_cmd = """
	SELECT login_time FROM USER_TBL WHERE username='{}';
	""".format(username)

	result = db.engine.execute(sql_cmd).fetchone()


	return result['login_time']

def set_login_time(login_time):
	username = current_user.get_id()
	sql_cmd = """
		UPDATE USER_TBL
		SET login_time={}
		WHERE username='{}'
	""".format(login_time,username)

	db.engine.execute(sql_cmd)

	return 

def get_total_view():
	sql_cmd = """
		select var_val from GV where var_name='total_view';
	"""
	total_view = db.engine.execute(sql_cmd).fetchone()['var_val']
	return total_view

def set_total_view(total_view):
	sql_cmd = """
		UPDATE GV
		SET var_val={}
		WHERE var_name='total_view';
	""".format(total_view)
	db.engine.execute(sql_cmd)
	return


def get_userID_by_username():
	sql_cmd = """
		SELECT user_id 
		from USER_TBL
		WHERE username='{}'
	""".format(current_user.get_id())

	result = db.engine.execute(sql_cmd).fetchone()
	if(result):
		return result['user_id']
	else:
		return None

def get_author_by_msgID(id):
	sql_cmd = """
		SELECT author 
		from MSG_TBL
		WHERE msg_id={}
	""".format(id)

	result = db.engine.execute(sql_cmd).fetchone()
	if(result):
		return result['author']
	else:
		return None

def leave_msg(user_id, msg):
	sql_cmd = """
		INSERT INTO MSG_TBL
		(message, user_id, author)
		VALUES ('{}', {}, '{}');
	""".format(msg,user_id,current_user.get_id())

	db.engine.execute(sql_cmd)

	return

def get_top_msg(offset=0, num=5):
	sql_cmd = """
		SELECT *
		from MSG_TBL
		order by msg_id desc
		offset {} limit {};
	""".format(offset, num)

	result = db.engine.execute(sql_cmd)
	msg = []
	for row in result:
		msg.append({
			'user_id':row['user_id'],
			'message':html.unescape(row['message']),
			'msg_id':row['msg_id'],
			'author':row['author']
			})
	return msg

def del_msg_by_id(msg_id):
	sql_cmd = """
	DELETE FROM MSG_TBL
	WHERE msg_id={};
	""".format(msg_id)

	db.engine.execute(sql_cmd)
	return

def total_msg():
	sql_cmd = """
	SELECT COUNT(*) FROM MSG_TBL;
	"""
	return db.engine.execute(sql_cmd).fetchone()['count']

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=1)

@app.route('/')
def index():
	count = 0
	
	total_view = 0
	total_view = get_total_view() + 1
	set_total_view(total_view)
	#count with cookie
	if(request.cookies.get("count",None)):
		count = int(request.cookies.get("count",None)) + 1
	else:
		count += 1

	render_page = render_template("index.html",count=count, total_view=total_view)

	resp = make_response(render_page)
	#set cookie back
	resp.set_cookie(key='count', value=str(count), expires=time.time()+6*60)
	return resp

@app.route('/msgboard', methods=['GET', 'POST'])
def msgboard():	
	#get message from data base
	page = int(request.args.get('page', 1))
	per_page = 5
	total = total_msg()
	offset = (page-1) * per_page
	msg = get_top_msg(offset,per_page)
	pagination = Pagination(page=page, per_page=per_page, total=total,inner_window=1,outer_window=0,
                            css_framework='bootstrap4')

	return render_template('msgboard.html',
							messages=msg,
							pagination=pagination)

@app.route('/say', methods=['GET', 'POST'])
def say():
	if request.method == 'GET':  
		   return render_template("msgboard.html")

	user_id = get_userID_by_username()
	msg = request.form['message']
	msg = XSSsanitize(msg)

	if(len(msg)>50):
		flash('your message too long!!!')
	elif(len(msg) == 0):
		flash('type something!!!')	
	elif(user_id):
		leave_msg(user_id, msg)
	else:
		flash('Something wrong!!!')		
	
	return redirect(url_for('msgboard')) 

@app.route('/del_msg', methods=['POST'])
def del_msg():
	# 1. check author and user is same guy
	# 2. delete the message
	msg_id = request.form['msg_id']
	if(get_author_by_msgID(msg_id) == current_user.get_id()):
		del_msg_by_id(msg_id)
	else:
		flash("you are not the author")
	
	return redirect(url_for('msgboard')) 


@app.route('/upload', methods=['GET', 'POST'])
@login_required  
def upload_img():
	if request.method == 'POST':
		# check if the post request has the file part
		if 'photo' not in request.files:
			return "No file!!!"

		photo = request.files['photo']
		# if user does not select file, browser also
		# submit a empty part without filename
		if photo.filename == '':
			flash('No selected file')
			return redirect(request.url)
		if photo and allowed_file(photo.filename):
			filename = secure_filename(photo.filename)
			ext = filename.split('.')[-1].lower()
			photo.save(os.path.join(app.config['UPLOAD_FOLDER'], "{}.{}".format(current_user.id,"png")))
		else:
			return "Don't hack me, plz!!!!"

	login_time = get_login_time()
	#login_time += 1
	#set_login_time(login_time)

	return render_template('upload.html', id=current_user.id, status = current_user.is_active, login_time = login_time)


@app.route('/login', methods=['GET', 'POST'])  
def login():  
	if request.method == 'GET':  
		   return render_template("login.html")

	account = request.form['id']
	password = request.form['password']

	if(not is_account_exist(account)):
		flash('Account or password incorrect!!!')
		return redirect(url_for('login'))

	if (is_pw_correct(account,password)):
		#login success!!!
		user = User()  
		user.id = account  
		#  這邊，透過login_user來記錄user_id，如下了解程式碼的login_user說明。  
		login_user(user)
		# add login times
		login_time = get_login_time()
		login_time += 1
		set_login_time(login_time)
		 
		return redirect(url_for('upload_img'))  
	
	flash('Account or password incorrect!!!')
	return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():  
	if request.method == 'GET':  
		   return render_template("login.html")

	account = request.form['id']  
	account_hat = re.sub("[^0-9a-z]","",account)
	
	password = request.form['password']  
	password_hat = re.sub("[^0-9a-z]","",password)

	if(password != password_hat or account != account_hat or len(account)<9 or len(password)==0):
		flash("Your ID or password invalid")
		return redirect(url_for('login'))

	if(is_account_exist(account)):
		flash("This ID has already existed!!!")
		return redirect(url_for('login'))

	else:
		create_user(account,password)
		flash('Thank you for registering, plz login again!!!')
		sample_img  = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], "{}.{}".format("sample","png"))) 
		sample_img.save(os.path.join(app.config['UPLOAD_FOLDER'], "{}.{}".format(account,"png")))
		return redirect(url_for('login')) 

@app.route('/logout', methods=['POST'])  
def logout():  
	logout_user()
	return 'Log out successfully!!!'
	
@app.route("/favicon.ico")
def favicon():
	
	return current_app.send_static_file('favicon.ico')

@app.after_request
def add_header(r):
	"""
	Add headers to both force latest IE rendering engine or Chrome Frame,
	and also to cache the rendered page for 10 minutes.
	"""
	r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
	r.headers["Pragma"] = "no-cache"
	r.headers["Expires"] = "0"
	r.headers['Cache-Control'] = 'public, max-age=0'
	r.headers['Warning'] = ' Don\'t fuck me!!!'

	return r

@login_manager.user_loader  
def user_loader(id):  
	if(not is_account_exist(id)):  
		return  
  
	user = User()  
	user.id = id  
	return user

if __name__ == '__main__':
	app.run()