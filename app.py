from flask import Flask, jsonify, render_template, request

import verifier

app = Flask(__name__)
MAX_ADDRESSES = 50


@app.get("/")
def index():
    return render_template("index.html", max_addresses=MAX_ADDRESSES)


@app.get("/api/status")
def status():
    return jsonify(smtp_enabled=verifier.smtp_available(), max=MAX_ADDRESSES)


@app.post("/api/check")
def check():
    data = request.get_json(silent=True) or {}
    addrs = verifier.parse_list(data.get("emails", ""))
    if not addrs:
        return jsonify(error="Paste at least one email address."), 400
    truncated = len(addrs) > MAX_ADDRESSES
    smtp = verifier.smtp_available()
    results = verifier.check_many(addrs[:MAX_ADDRESSES], smtp=smtp)
    return jsonify(results=results, smtp_enabled=smtp, truncated=truncated, total=len(addrs))


if __name__ == "__main__":
    app.run(debug=True)
