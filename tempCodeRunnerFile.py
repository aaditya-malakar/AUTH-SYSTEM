@app.route("/resend_code", methods=["POST"])
def resend_code():
    email = request.form.get("email")

    if not email:
        return render_template("verify.html", msg="Email not found in form")

    new_code = str(secrets.randbelow(900000) + 100000)

    global code
    code = new_code

    webhook_url = "https://aadityamalakar.app.n8n.cloud/webhook/webhook-email-code"
    requests.post(webhook_url, json={
        "email": email,
        "code": new_code,
    })

    return render_template("verify.html", resent=f"New code sent to {email}", email=email)