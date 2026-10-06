from flask import Flask, render_template, request
from feature_extractor import extract_features
from model import predict_url
from database import create_database, save_history, get_history
from urllib.parse import urlparse

app = Flask(__name__)

# Create database when application starts
create_database()


def is_valid_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception:
        return False


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    features = None
    risk_score = None

    if request.method == "POST":

        url = request.form["url"].strip()

        if not is_valid_url(url):

            result = "❌ Please enter a valid URL starting with http:// or https://"

        else:

            # Extract URL features
            features = extract_features(url)

            # Predict URL
            result = predict_url(features)

            # Save result in database
            save_history(url, result, features)

    return render_template(
    "index.html",
    result=result,
    risk_score=risk_score,
    features=features
)


@app.route("/history")
def history():

    history_data = get_history()

    return render_template(
        "history.html",
        history=history_data
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)