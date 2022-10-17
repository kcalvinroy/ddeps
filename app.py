
# Libraries imported
import os
import re
import urllib
import hashlib
import datetime
import requests
import urllib.request
from fileinput import filename
from datetime import timedelta
import mysql.connector as database
from flask_login import current_user
from pinata_python.pinning import Pinning
from werkzeug.utils import secure_filename
from flask import Flask,render_template, redirect, request, url_for, session, send_file, g

# Pinata API key, secret and gateway
pinata_api_key = '3d1b8d4bf3c95fe38eaa'
pinata_api_secret = 'ee7d3d7022a5f5cdd8aaf9f161b0f7f97bfbf530d3955c86ba0cf3ad348dd145'
pinata = Pinning(PINATA_API_KEY=pinata_api_key, PINATA_API_SECRET=pinata_api_secret)
gateway="https://ipfs.io/ipfs/"

UPLOAD_FOLDER = '/home/ck/Desktop/DigEvid/DDEPS/uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER 
app.secret_key = '12345678'
salt = "5gz69"

connection = database.connect(user = 'admin', password = '12345678', host='localhost', database = 'dedb')
connection1 = database.connect(user = 'admin', password = '12345678', host='localhost', database = 'dedb')
connection2 = database.connect(user = 'admin', password = '12345678', host='localhost', database = 'dedb')
connection3 = database.connect(user = 'admin', password = '12345678', host='localhost', database = 'dedb')
cursor = connection.cursor()
cursor1 = connection1.cursor()
cursor2 = connection2.cursor()
cursor3 = connection3.cursor()

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True
    g.user = current_user

@app.route("/", methods=['GET'])
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Message incase something goes wrong
    msg = ''
    # Checks on password and user name
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        #variables for easy access
        username = request.form['username']
        password = request.form['password']
        password=password+salt
        h = hashlib.md5(password.encode())
        password=str(h.hexdigest())
        cursor.execute('SELECT * FROM user WHERE username = %s AND password = %s', (username, password))
        # Fetch record and return result
        account = cursor.fetchone()
        # return hh.hexdigest()
        # if account exists
        if account:
            # CREATE session data, accessible in other routes
            session.clear()
            session['loggedin'] = True
            session['userID']=account[0]
            session['username']=account[1]
            session['email']=account[2]
            session['roleID']=str(account[4])
            # return session['roleID']
            #redirect to homepage
            return redirect(url_for('cases'))
        else:
            # Account not in existance or incorect logins
            msg = 'Incorrect username/password!'
    return render_template('login.html', msg=msg)

@app.route("/cases", methods=['GET', 'POST'])
def cases():
    if 'loggedin' in session:
        username=session['username']
        userID=str(session['userID'])
        # return session['roleID']
        # roleID=str(session['roleID'])
        # # return name1
        if session['roleID'] == '0' or session['roleID'] == '1':
            cursor.execute('SELECT case_file.caseID, name, status, datecreated FROM case_file join assigned on case_file.caseID=assigned.caseID where assigned.userID='+userID)
        else:    
            cursor.execute('SELECT * FROM case_file')
    else:
        return redirect(url_for('login'))
    return render_template("cases.html", username=username, cursor=cursor, RoleID=session['roleID'])

@app.route('/logout')
def logout():
    # Remove session data, logging out the user
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    #Redirect to login page
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    if 'loggedin' in session:
        if session['roleID'] == '2' or session['roleID'] == '3':
            if request.method == 'POST' and 'username' in request.form and 'email' in request.form and 'password' in request.form and 'roleID' in request.form:
                #variables for easy access
                try:
                    username = str(request.form['username'])
                    email = str(request.form['email'])
                    password = (request.form['password'])
                    roleID = (request.form['roleID'])
                    # check if account exists
                    cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
                    account = cursor.fetchone()
                    # If account exists show error and validation checks
                    if account:
                        msg = 'Account already exits!'
                    elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                        msg='Invalid email address!'
                    elif not re.match(r'[A-Za-z0-9]+', username):
                        msg = 'Username must only contain characters and numbers!'
                    elif not username or not password or not email:
                        msg = 'Please fill out the form!'
                    else:
                        password=password+salt
                        h = hashlib.md5(password.encode())
                        password=str(h.hexdigest())
                        #Account doesnt exist and form data is valid, now insert new account into accounts table
                        cursor.execute('INSERT INTO user(username, email, password, roleID) VALUES(%s, %s, %s, %s)', (username, email, password, roleID,))
                        connection.commit()
                        mes = 'Successfully registered!'
                except database.Error as e:
                    msg='Error Creating c: {e}' 
            elif request.method == 'POST':
                        # Form is empty
                        msg = 'Please fill in the form'
            
    return render_template("register.html", mes=mes, msg=msg, RoleID=session['roleID'])

@app.route("/edit_user_<string:userID>", methods=['GET', 'POST'])
def edit_user(userID):
    userid=str(userID)
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    
    if 'loggedin' in session:
        session['roleID']
        if request.method == 'POST' and 'username' in request.form and 'email' in request.form and 'password' in request.form and 'roleID' in request.form:
            #variables for easy access
            try:
                username = str(request.form['username'])
                email = str(request.form['email'])
                password = (request.form['password'])
                roleID = (request.form['roleID'])
                if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg='Invalid email address!'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'Username must only contain characters and numbers!'
                elif not username or not password or not email:
                    msg = 'Please fill out the form!'
                else:
                    password=password+salt
                    h = hashlib.md5(password.encode())
                    password=str(h.hexdigest())
                    #Account doesnt exist and form data is valid, now insert new account into accounts table
                    cursor.execute('UPDATE user SET username=%s, email=%s, password=%s, roleID=%s WHERE userID = %s', (username, email, password, roleID, userid))
                    connection.commit()
                    mes = 'Successfully Edited!'
            except database.Error as e:
                msg='Error editing: {e}'
            return redirect(url_for('users'))
        elif request.method == 'POST':
                    # Form is empty
                    msg = 'Please fill in the form'
        cursor2.execute('SELECT * FROM user WHERE userID ='+userid)
            
    return render_template("edit_user.html", mes=mes, msg=msg, cursor2=cursor2, RoleID=session['roleID'])

@app.route("/add_case", methods=['GET', 'POST'])
def add_case():
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    if 'loggedin' in session:
        if request.method == 'POST' and 'name' in request.form and 'status' in request.form:
            #variables for easy access
            try:
                name = str(request.form['name'])
                status = str(request.form['status'])
                cursor.execute('INSERT INTO case_file(name, status) VALUES(%s, %s)', (name, status))
                connection.commit()
                mes='Successfully Created case'
            except database.Error as e:
                msg='Error Creating case: {e}'
    return render_template("add_case.html", mes=mes, msg=msg, RoleID=session['roleID'])

@app.route("/edit<int:caseID>", methods=['GET', 'POST'])
def edit(caseID):
    caseid=str(caseID)
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    cursor2.execute('SELECT * from case_file where caseID='+caseid)
    if 'loggedin' in session:
        if request.method == 'POST' and 'name' in request.form and 'status' in request.form:
            #variables for easy access
            try:
                name = str(request.form['name'])
                status = str(request.form['status'])
                cursor.execute('UPDATE case_file SET name=%s, status=%s where caseID=%s', (name, status,caseid))
                connection.commit()
                mes='Successfully Edited case'
            except database.Error as e:
                msg='Error editing case: {e}'
    return render_template("edit_case.html", mes=mes, msg=msg,  cursor2 = cursor2, RoleID=session['roleID'])

@app.route("/add_evidence_<string:caseID>", methods=['GET', 'POST'])
def add_evidence(caseID):
    caseid=caseID

    return render_template("add_evidence.html", caseID=caseid, RoleID=session['roleID'])


@app.route("/evidence", methods=['GET', 'POST'])
def evidence():
    if 'loggedin' in session:
        username=session['username']
        # cases
        cursor.execute('SELECT * FROM evidence')
    else:
        return redirect(url_for('login'))
    return render_template("evidence.html", cursor=cursor, RoleID=session['roleID'])

@app.route('/upload', methods = ['GET', 'POST'])
def upload_file():
    mes=''
    msg=''
    caseID = str(request.form['caseID'])
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    filepath=UPLOAD_FOLDER+'/'+filename
    filepath=str(filepath)
    response = pinata.pin_file_to_ipfs(filepath)
    cid=response['IpfsHash']
    size=response['PinSize']
    cursor.execute('INSERT INTO `evidence` (`caseID`, `filename`, `hash`) VALUES(%s, %s, %s)',(caseID, filename, cid))
    connection.commit()
    mes = 'Evidence file uploaded successfully'
    os.remove('uploads/'+filename)
    return render_template("add_evidence.html", msg=msg, mes=mes, RoleID=session['roleID'])


@app.route('/download_<string:hash>', methods = ['GET', 'POST'])
def download(hash):
    file_hash=str(hash)
    cursor.execute('SELECT filename FROM evidence WHERE hash="'+hash+'"')
    for filename in cursor:
        filenames=str(filename)
        name1=filenames.replace(",","")
        name1=name1.replace("'","")
        name1=name1.replace("(","")
        name1=name1.replace(")","")
        link=gateway+file_hash
        r=urllib.request.urlopen(link)
    return send_file(r, as_attachment=True, download_name=name1) 

@app.route("/report_<string:evid>", methods=['GET', 'POST'])
def report(evid):
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    uid=str(session['userID'])
    if 'loggedin' in session:
        uid=str(session['userID'])
        evidence=str(evid)
        cursor.execute('SELECT caseID, filename, hash, timestamp FROM evidence WHERE evidenceID ='+evidence)
        evi=cursor.fetchone()
        case=evi[0]
        file=evi[1]
        has=evi[2]
        tim=evi[3]
        if request.method == 'POST' and 'caseID' in request.form and 'evidenceID' in request.form and 'userID' in request.form and 'data' in request.form:
            #variables for easy access
            try:
                caseID = str(request.form['caseID'])
                evidenceID = str(request.form['evidenceID'])
                userID = str(request.form['userID'])
                data = str(request.form['data'])
                cursor.execute('INSERT INTO report(caseID, evidenceID, userID, data) VALUES(%s, %s, %s, %s)', (caseID, evidenceID, userID, data))
                connection.commit()
                mes='Successfully submitted'
                uid=str(session['userID'])

            except database.Error as e:
                msg='Error submitting report: {e}'
    return render_template("report.html", mes=mes, msg=msg, userID=uid, evidenceID=evidence, caseID=case, filename=file, hash=has, timestamp=tim, RoleID=session['roleID'])


@app.route("/add_report", methods=['GET', 'POST'])
def add_report():
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    uid=str(session['userID'])
    if 'loggedin' in session:
        if request.method == 'POST' and 'caseID' in request.form and 'evidenceID' in request.form and 'userID' in request.form and 'data' in request.form:
            #variables for easy access
            try:
                caseID = str(request.form['caseID'])
                evidenceID = str(request.form['evidenceID'])
                userID = str(request.form['userID'])
                data = str(request.form['data'])
                cursor.execute('INSERT INTO report(caseID, evidenceID, userID, data) VALUES(%s, %s, %s, %s)', (caseID, evidenceID, userID, data))
                connection.commit()
                mes='Successfully submitted'
                return redirect(url_for('reports'))
            except database.Error as e:
                msg='Error submitting report: {e}'
        if request.method == 'GET':
            uid=str(session['userID'])
        
    return render_template("add_report.html", mes=mes, msg=msg, userID=uid, RoleID=session['roleID'])

@app.route("/view_report_<string:reportID>", methods=['GET', 'POST'])
def view_report(reportID):
    reportid=str(reportID)
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    uid=str(session['userID'])
    if 'loggedin' in session:
        cursor2.execute('SELECT * FROM report where reportID='+reportid)
        for (reportID, caseID, evidenceID, userID, data) in cursor2:
            reportID=reportID
            caseID=caseID
            evidenceID=str(evidenceID)
            userID=userID
            data=data
        cursor.execute('SELECT * FROM evidence WHERE evidenceID ='+evidenceID)

        
        
    return render_template("view_report.html", mes=mes, msg=msg, cursor2=cursor, cursor=cursor, reportID=reportID, caseID=caseID, evidenceID=evidenceID, userID=userID, data=data, RoleID=session['roleID'])

@app.route("/reports", methods=['GET', 'POST'])
def reports():
    if 'loggedin' in session:
        username=session['username']
        # cases
        cursor.execute('SELECT * FROM report')
    else:
        return redirect(url_for('login'))
    return render_template("reports.html", cursor=cursor, RoleID=session['roleID'])


@app.route("/view_reports_<string:evidenceID>", methods=['GET', 'POST'])
def view_reports(evidenceID):
    evidenceid=str(evidenceID)
    if 'loggedin' in session:
        username=session['username']
        cursor.execute('SELECT * FROM report where evidenceID='+evidenceid)
        cur=cursor.fetchall()
    else:
        return redirect(url_for('login'))
    return render_template("reports.html", cursor=cur, RoleID=session['roleID'])


@app.route("/del_report_<string:reportID>", methods=['GET', 'POST'])
def del_report(reportID):
    reportid=reportID
    if 'loggedin' in session:
        cursor.execute('DELETE FROM report WHERE reportID='+reportid)
        connection.commit()
    else:
        return redirect(url_for('login'))
    return redirect(url_for('reports'))

@app.route("/del_user_<string:userID>", methods=['GET', 'POST'])
def del_user(userID):
    userid=userID
    if 'loggedin' in session:
        cursor.execute('DELETE FROM user WHERE userID='+userid)
        connection.commit()
    else:
        return redirect(url_for('login'))
    return redirect(url_for('users'))

@app.route("/del_assigned_<string:userID>_<string:caseID>", methods=['GET', 'POST'])
def del_assigned(userID, caseID):
    userid=userID
    caseid=caseID
    if 'loggedin' in session:
        cursor.execute('DELETE FROM assigned WHERE userID='+userid+' and caseID='+caseid)
        connection.commit()
    else:
        return redirect(url_for('login'))
    return redirect(url_for('case', caseID=caseid))

@app.route("/update_report_<string:reportID>_<string:data>", methods=['GET', 'POST'])
def update_report(reportID, data):
    reportid=str(reportID)
    udata=str(data)
    if 'loggedin' in session:
        cursor.execute('UPDATE report SET data=%s WHERE reportID=%s', (reportid, udata))
        connection.commit()
        mes='Successfully submitted'
    else:
        return redirect(url_for('login'))
    return redirect(url_for('view_report', reportID=reportid))


@app.route("/users", methods=['GET', 'POST'])
def users():
    if 'loggedin' in session:
        username=session['username']
        userid=str(session['userID'])
        # cases
        role=['Investigator', 'Analyst', 'Chief Investigator', 'Admin']
        if session['roleID'] == '0' or session['roleID'] == '1':
            cursor.execute('SELECT * FROM user where userID='+userid)
        else:
            cursor.execute('SELECT * FROM user')
    else:
        return redirect(url_for('login'))
    return render_template("users.html", role=role, cursor=cursor, RoleID=session['roleID'])

@app.route("/<int:caseID>", methods=['GET', 'POST'])
def case(caseID):
    caseid=str(caseID)
    mes=''
    msg=''
    if 'loggedin' in session:
        cursor.execute('SELECT userID, username FROM user WHERE roleID<2')
        available_users=cursor.fetchall()
        cursor.execute('SELECT * FROM evidence WHERE caseID='+str(caseid))
        case_evidence=cursor.fetchall()
        cursor2.execute('SELECT user.userID, user.username, user.roleID from user join assigned on user.userID=assigned.userID where assigned.caseID='+str(caseid))
        cursor.execute('SELECT * FROM case_file WHERE caseID='+str(caseid))
        for (caseID, name, status, datecreated) in cursor:
            cID=caseID
            nm=name
            stat=status
            dc=datecreated
    else:
        return redirect(url_for('login'))

    return render_template("case.html", case_evidence=case_evidence, caseID=cID, name=nm, status=stat, datecreated=dc, cursor1=cursor, cursor2=cursor2, available_users=available_users, RoleID=session['roleID'])

@app.route("/assign_<string:caseID>", methods=['GET', 'POST'])
def assign(caseID):
    caseid=caseID
    if 'loggedin' in session:
        if request.method == 'POST' and 'caseID' in request.form and 'userID' in request.form:
            try:
                caseID = str(request.form['caseID'])
                userID = str(request.form['userID'])
                cursor.execute('INSERT INTO assigned VALUES(%s, %s)', (caseID, userID))
                connection.commit()
                mes='Successfully Assigned'
            except database.Error as e:
                msg='Error Assigning: {e}'
    else:
        return redirect(url_for('login'))
    return redirect(url_for('case', caseID=caseid))

@app.route("/<int:caseID>_<int:userID>_remove", methods=['GET'])
def remove(caseID, userID):
    caseid=str(caseID)
    userid=str(userID)
    if 'loggedin' in session:
            try:
                cursor.execute('DELETE FROM assigned WHERE caseID=%s AND userID=%s', (caseid,userid))
                connection.commit()
                mes='Successfully Removed'
            except database.Error as e:
                msg='Error Removing: {e}'
    else:       
        return redirect(url_for('login'))
    return redirect(url_for('case', caseID=caseid))

if __name__ == '__main__':
    app.run(debug = True)