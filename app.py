from flask import Flask, jsonify, render_template, request, Response
import crypto_core as cc

app = Flask(__name__)
S = {}  # In-memory demo state; restarting Flask clears it.

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/setup")
def setup():
    ca_key, ca_cert = cc.make_ca()
    identity_key, identity_cert = cc.issue(ca_key, ca_cert, cn="Aditya", email="aditya@example.com")
    S.clear()
    S.update(ca=ca_cert, alice=identity_cert, alice_key=identity_key, sig=None)
    identity_info = cc.info(identity_cert)
    # Return both keys for compatibility with older/newer frontend versions.
    return jsonify(ca=cc.info(ca_cert), alice=identity_info, aditya=identity_info)

@app.post("/api/sign")
def sign():
    if not S.get("ca") or not S.get("alice_key"):
        return jsonify(error="Create the CA and certificate first."), 400
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").encode("utf-8")
    if not message:
        return jsonify(error="Type a message to sign."), 400
    signature = cc.sign(S["alice_key"], message)
    S["sig"] = signature
    S["signed_message"] = message
    return jsonify(hash=cc.sha256(message), signature=signature.hex(), bytes=len(signature))

@app.post("/api/verify")
def verify():
    if not S.get("sig"):
        return jsonify(error="Sign a message first."), 400
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").encode("utf-8")
    cert, signature = S["alice"], S["sig"]
    if data.get("forged"):
        # Demonstration: a different, untrusted CA signs a look-alike identity certificate.
        rogue_key, rogue_ca = cc.make_ca("Rogue CA", "Evil Corp")
        rogue_identity_key, cert = cc.issue(rogue_key, rogue_ca, cn="Aditya", email="aditya@example.com")
        signature = cc.sign(rogue_identity_key, message)
    ok, checks = cc.verify(cert, S["ca"], message, signature)
    return jsonify(ok=ok, checks=checks, hash=cc.sha256(message), cert=cc.info(cert))

@app.get("/download/<which>")
def download(which):
    cert = S.get({"ca": "ca", "alice": "alice", "aditya": "alice"}.get(which, ""))
    if cert is None:
        return "Create the certificates first.", 404
    return Response(
        cc.pem(cert),
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={which}_cert.pem"},
    )

if __name__ == "__main__":
    print("Open http://127.0.0.1:5000")
    app.run(debug=False)
