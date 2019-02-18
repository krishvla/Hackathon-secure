from flask import Flask,render_template,request, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
import socket
from flask_bootstrap import Bootstrap
from wtforms import Form, StringField, IntegerField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
from flask_wtf import FlaskForm
app = Flask(__name__)
app.secret_key = 'some secret key'
#config MySQL
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='hack'
app.config['MYSQL_PASSWORD']='password'
app.config['MYSQL_DB']='secure'
app.config['MYSQL_CURSORCLASS']='DictCursor'
#initialize MySQL
mysql = MySQL(app)


#==================================================FOrms=============================================
@app.route('/tye')
def type():
	cur = mysql.connection.cursor()
	cur.execute("SELECT sym FROM symptoms")
	test = cur.fetchall()

class RegisterForm(Form):
	login_id = StringField('Login Id',[validators.DataRequired()])
	name = StringField('First Name',[validators.Length(min=5,max=100)])
	role = SelectField('Role', choices = [])
	phone_number = IntegerField('Phone Number')
	password=PasswordField('Password',[
			validators.DataRequired(),
			validators.EqualTo('confirm', message='Password do not match')
	])
	confirm= PasswordField('Confirm Password')
class mess(Form):
	message=TextAreaField('Message',[validators.DataRequired()]) 
class addpatient(Form):
	p_id = StringField('Patient Id',[validators.DataRequired])
	u_id = StringField('IP Id',[validators.DataRequired])
	location =  SelectField('Location', choices = [('Nellore', 'NELLORE'),('Trunk Road', 'Trunk Road'),('Bypass','Bypass')])


#=================================================End Forms==========================================
def get_Host_name_IP(): 
    try: 
        host_name = socket.gethostname() 
        host_ip = socket.gethostbyname(host_name)
        print("IP : ",host_ip) 
    except: 
        print("Unable to get Hostname and IP") 
  
# Driver code 
get_Host_name_IP()

#security
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized , Please Login', 'danger')
			return render_template('login.html')
	return wrap

@app.route('/')
def index():
 	return render_template('home.html')

@app.route('/About')
def About():
	return render_template('About.html')
@app.route('/Home')
def Home():
	return render_template('home.html')

@app.route('/sugg')
def prevention():
	return render_template('prevention.html')
@app.route('/register',methods=['GET', 'POST'])
def register():

	#import register()
	cur = mysql.connection.cursor()
	form = RegisterForm(request.form)
	form.role.choices = [cur.execute("SELECT sym FROM symptoms")]
	if request.method == 'POST' and form.validate():
		login_id = form.login_id.data
		name = sha256_crypt.encrypt(str(form.name.data))
		phone_number = form.phone_number.data
		password = sha256_crypt.encrypt(str(form.password.data))
		role = form.role.data
		# create DictCursor
		cur = mysql.connection.cursor()
		cur.execute("INSERT INTO user(login_id, name,  phone_number, password, role)VALUES(%s, %s, %s, %s, %s)", (login_id, name, phone_number, password, role))
		#commit to 
		mysql.connection.commit()
		cur.close()
		flash('Registered Successfully!!!', 'success')
		redirect(url_for('Home'))

	return render_template('register.html', form=form)
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		#Getting form fields
		login_id = request.form['login_id']
		logid = request.form['login_id']
		l=logid
		password_candidate = request.form['password']
		# print(login_id)
		if login_id == '12345':

		# create cursor
			cur = mysql.connection.cursor()

		#getting user name
			result = cur.execute("SELECT * FROM user WHERE login_id = %s", [login_id])

			if result >0:
			# Get Stored hash
				data = cur.fetchone()
				password = data['password']

			# checking
				if sha256_crypt.verify(password_candidate, password):
					app.logger.info('PASSWORD MATCHED')
					session['logged_in'] = True
					session['login_id'] = login_id
					return redirect(url_for('dashboard'))
				else:
					app.logger.info('PASSWORD NOT MATCHED')
					flash('Password Not Matched!! Try Again','danger')
					return render_template('login.html')
				#close
				cur.close()

			else:
				flash('No User Exsists With That Login Id!!\n Try With Valid Login ID ','danger')
				app.logger.info('NO USER')
		elif login_id != '12345':
			# create cursor
			cur = mysql.connection.cursor()

		#getting user name
			result = cur.execute("SELECT * FROM user WHERE login_id = %s", [login_id])

			if result >0:
			# Get Stored hash
				data = cur.fetchone()
				password = data['password']
				role = data['role']
				status = data['status']

			# checking
				if sha256_crypt.verify(password_candidate, password):
					app.logger.info('PASSWORD MATCHED')
					session['logged_in'] = True
					session['login_id'] = login_id
					if role == 'Ip' and status =='y':
						return redirect(url_for('ipdashboard'))
					elif role == 'user' and status == 'y':
						cur.execute("SELECT * FROM up WHERE login_id=%s",[login_id])
						update = cur.fetchall()
						return render_template('userdashboard.html',update=update)
					else:
						flash('Your Verification is Under Process', 'danger')
						return render_template('login.html')
				else:
					app.logger.info('PASSWORD NOT MATCHED')
					flash('Password Not Matched!! Try Again','danger')
					return render_template('login.html')
				#close
				cur.close()
			else:
				flash('No User Exsists With That Login Id!!\n Try With Valid Login ID','danger')
				app.logger.info('NO USER')
		
	
	return render_template('login.html')
#logout
@app.route('/logout')
def logout():
	session.clear()
	flash('your logged out', 'success')
	return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
	cur = mysql.connection.cursor()
	cur.execute("SELECT * FROM user")
	user = cur.fetchall()
	cur.execute("SELECT * FROM results")
	res = cur.fetchall()
	return render_template('dashboard.html',user=user,res=res)

@app.route('/cs/<string:login_id>', methods=['GET', 'POST'])
@is_logged_in
def cs(login_id):
	#create Cursor
	cur = mysql.connection.cursor()
	cur.execute("UPDATE user SET status='y' WHERE login_id=%s",[login_id])
	mysql.connection.commit()
	cur.close()
	return redirect(url_for('dashboard'))
@app.route('/diagnosis/<string:login_id>',methods=['GET', 'POST'])
@is_logged_in
def diagnosis(login_id):
	p_id = login_id
	print(p_id)
	cur=mysql.connection.cursor()
	cur.execute("SELECT * FROM symptoms WHERE type!='1' and type!='2' and type!='3'")
	diag=cur.fetchall()
	cur.execute("SELECT * FROM symptoms WHERE type=1 or type=2 or type=3")
	spe = cur.fetchall()
	print(spe)
	cur.close()
	return render_template('diagnosis.html',diag=diag,p_id=p_id,spe=spe)
@app.route('/<string:login_id>/<string:s_id>',methods=['POST', 'GET'])
@is_logged_in
def adding(login_id,s_id):
	p_id = login_id
	sym_id = s_id
	print("Pid is :",p_id)
	print("Sym_id is: ",sym_id)
	cur=mysql.connection.cursor()
	cur.execute("SELECT * FROM results WHERE p_id=%s",[p_id])
	find = cur.fetchone()
	print("Find is: ",find)
	if find>0:
		cur.execute("SELECT type FROM symptoms WHERE id=%s",[sym_id])
		re=cur.fetchone()
		typ = re['type']
		cur.execute("SELECT * FROM results WHERE p_id=%s",[p_id])
		count = cur.fetchone()
		if typ=='at':
			res = int(count['at'])+1
			cur.execute("UPDATE results SET at=%s WHERE p_id=%s",[res,p_id])
			mysql.connection.commit()
			cur.close()
		elif typ=='pt':
			res=int(count['pt'])+1
			cur.execute("UPDATE results SET pt=%s WHERE p_id=%s",[res,p_id])
			mysql.connection.commit()
			cur.close()
		elif typ=='et':
			res = int(count['et'])+1
			cur.execute("UPDATE results SET et=%s WHERE p_id=%s",[res,p_id])
			mysql.connection.commit()
			cur.close()
		elif typ=='pd':
			res = int(count['pd'])+1
			cur.execute("UPDATE results SET pd=%s WHERE p_id=%s",[res,p_id])
			mysql.connection.commit()
			cur.close()
		elif typ=='1':
			cur.execute("UPDATE results SET special='Lymph Node TB' WHERE p_id=%s",[p_id])
			mysql.connection.commit()
			cur.close()
		elif typ=='2':
			cur.execute("UPDATE results SET special='Genitowinar' WHERE p_id=%s",[p_id])
			mysql.connection.commit()
			cur.close()
		elif typ=='3':
			cur.execute("UPDATE results SET special='Gastrointestinal' WHERE p_id=%s",[p_id])
			mysql.connection.commit()
			cur.close()
	else:
		cur=mysql.connection.cursor()
		cur.execute("INSERT INTO results(p_id,at,pt,et,pd)VALUES(%s,%s,%s,%s,%s)",(p_id,0,0,0,0))
		mysql.connection.commit()
		cur.close()
		flash("Patient is Added",'danger')

	return redirect(url_for('ipdashboard'))

@app.route('/results/<string:login_id>',methods=['GET','POST'])
@is_logged_in
def results(login_id):
	p_id = login_id
	cur = mysql.connection.cursor()
	cur.execute("SELECT * FROM results WHERE p_id=%s",[p_id])	
	result = cur.fetchone()
	spe=result['special']
	total = int(result['at'])+int(result['pt'])+int(result['et'])+int(result['pd'])
	print("total s", total)
	p_at = int((float(result['at'])/total)*100)
	p_pt = int((float(result['pt'])/total)*100)
	p_et = int((float(result['et'])/total)*100)
	p_pd = int((float(result['pd'])/total)*100)
	print(p_et)
	return render_template('results.html',p_at=p_at,p_pt=p_pt,p_et=p_et,p_pd=p_pd,p_id=p_id,spe=spe)

@app.route('/userdashboard')
def userdashboard():
	cur = mysql.connection.cursor()
	cur.execute("SELECT * FROM up WHERE login_id=%s",[login_id])
	update = cur.fetchall()
	cur.close()
	return render_template('userdashboard.html',update = update)
@app.route('/ipdashboard')
def ipdashboard():
	return render_template('ipdashboard.html')
@app.route('/addpatient',methods=['POST', 'GET'])
@is_logged_in
def patient():
	#import register()
	form = addpatient(request.form)
	if request.method == 'POST':
		p_id = form.p_id.data
		login_id = form.u_id.data
		location = form.location.data
		print(p_id)
		print(location)
		print(login_id)
		# create DictCursor
		cur = mysql.connection.cursor()
		cur.execute("SELECT phone_number FROM user WHERE login_id=%s",[p_id])
		result = cur.fetchone()
		phone_number = result['phone_number']
		cur.execute("INSERT INTO patient(login_id, underid, location, phone_number)VALUES(%s, %s, %s, %s)", (p_id, login_id, location, phone_number))
		#commit to 
		mysql.connection.commit()
		cur.close()
		return redirect(url_for('ipdashboard'))
	return render_template('addpatient.html', form=form)	
@app.route('/msg/<string:uid>/<string:login_id>', methods=['GET', 'POST'])
@is_logged_in
def msg(uid,login_id):
	#create Cursor
	form = mess(request.form)
	message = form.message.data
	if len(message)>0:
		cur = mysql.connection.cursor()
		cur.execute("INSERT INTO up(login_id, message, ref_by) VALUES(%s, %s, %s)",[login_id, message, uid])
		mysql.connection.commit()
		cur.close()
		flash('Message sended Successfully','success')
	else:
		flash('Empty Message cannot be sent','danger')
	return render_template('messag.html', form=form)

@app.route('/totalpatients/<string:login_id>', methods=['GET', 'POST'])
@is_logged_in
def totalpatients(login_id):
	#create Cursor
	cur = mysql.connection.cursor()
	cur.execute("SELECT * FROM patient WHERE underid=%s",[login_id])
	plist = cur.fetchall()
	mysql.connection.commit()
	cur.close()
	return render_template('list.html', plist=plist)

if __name__=='__main__':
	app.secret_key = 'some secret key'
    #ebug(True)
	app.run(host='0.0.0.0', port=8080, debug=True)
