from flask import Flask, render_template, request, session
import os, requests
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client
from dotenv import load_dotenv
import secrets, time

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

supa_key=os.environ.get("SUPA_API_KEY")
supa_url=os.environ.get("SUPA_URL")

supabase=create_client(supa_url, supa_key)

code_time=None
last_resend=None

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/reg", methods=["GET", "POST"])
def register():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")
        cpassword=request.form.get("cpassword")
        email=request.form.get("mail")
        fullname=request.form.get("Full_Name")
        role="user"

        session['code'] = str(secrets.randbelow(900000) + 100000)
        session['email'] = email
        session['code_time'] = time.time()

        if password==cpassword:
            users=(supabase.table("micro_route").select("username", "password", "role", "email").execute()).data
            for u in users:
                if u.get("username")==username:   
                    return render_template("register.html", msg="Username exists, login instead")
                
            for e in users:
                if e.get("email")==email:   
                    return render_template("register.html", msg="E-Mail already in use, use other E-Mail")

            hashed_pass=generate_password_hash(password)

            session['temp'] = {"username": username, "password": hashed_pass, "role": role,
                   "email": email, "fullname": fullname}

            code=session.get("code")

            webhook_url="https://aadityamalakar.app.n8n.cloud/webhook/webhook-email-code"

            requests.post(webhook_url, json={
                "email":email,
                "code": code,
            })

            session['code_time'] = time.time()

            return render_template("verify.html", msg=f"Kindly enter the code sent to your E-Mail: {email}")

        else:
            return render_template("register.html", msg="Passwords do not match")

    else:
        return render_template("register.html")
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")

        users = supabase.table("micro_route").select("username", "password", "role", "email", "fullname").execute()
        roles=users.data

        for r in roles:
            if r["username"]==username:
                if check_password_hash(r["password"], password):
                    if r["role"]=="user":
                        return render_template("user_dash.html")
                    else:
                        return render_template("admin_Dash.html")
                else:
                    return render_template("login.html", msg="Incorrect Password")
            pass
        
        else:
            return render_template("login.html", msg="You are not registered or username is incorrect")
        
    else:
        return render_template("login.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    code_time = session.get('code_time')
    stored_code = session.get('code')
    temp_data = session.get('temp')

    if request.method=="POST":
        code_input=request.form.get("code")
        now=time.time()

        if code_time and (now - code_time) > 300:
            return render_template("verify.html", result="Code expired! Please resend a new one.")

        if stored_code == code_input:
            supabase.table("micro_route").insert(temp_data).execute()
            session.pop('temp', None)
            session.pop('code', None)
            session.pop('email', None)
            session.pop('code_time', None)
            return render_template("user_dash.html")
        else:
            return render_template("verify.html", result="Incorrect Code")
        
    else:
        return render_template("verify.html")

@app.route("/resend_code", methods=["POST"])
def resend_code():
    last_resend=session.get("last_resend")
    now=time.time()

    if last_resend and (now - last_resend) < 120:
        wait = int(120 - (now - last_resend))    
        return render_template("verify.html", result=f"Wait {wait} seconds before resending.", msg=f"Kindly enter the code sent to your E-Mail: {session.get('email')}")

    new_code = str(secrets.randbelow(900000) + 100000)

    session['code'] = new_code
    session['last_resend'] = now
    session['code_time'] = now

    webhook_url = "https://aadityamalakar.app.n8n.cloud/webhook/webhook-email-code"
    requests.post(webhook_url, json={
        "email": session.get("email"),
        "code": new_code,
    })

    return render_template("verify.html", result="Code has been resent", email=session.get("email"), msg=f"Kindly enter the code sent to your E-Mail: {session.get("email")}")

if __name__=="__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
