from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, Vulnerable Flask World on Windows!"

if __name__ == "__main__":
    app.run(debug=True)
