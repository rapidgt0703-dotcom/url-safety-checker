import joblib

# Load trained model
model = joblib.load("model.pkl")


def predict_url(features):

    # --------------------------------------------------
    # ML prediction
    # --------------------------------------------------

    data = [[

        features["URL Length"],
        int(features["Uses HTTPS"]),
        features["Number of Dots"],
        features["Number of Hyphens"],
        features["Number of Digits"],
        features["Number of Slashes"],
        features["Number of Question Marks"],
        features["Number of Equals"],
        features["Number of Ampersands"],
        features["Number of Special Characters"],

        features["Domain Length"],
        features["Path Length"],

        int(features["Has IP Address"]),
        int(features["Has @ Symbol"]),
        int(features["Has Punycode"]),

        features["Number of Subdomains"],

        int(features["Has URL Encoding"]),
        features["Number of Encoded Characters"],

        int(features["Has Unusual Port"]),
        features["Port Number"],

        int(features["Has Double Slash"]),

        int(features["Is URL Shortener"]),

        int(features["Has Suspicious TLD"]),

        int(features["Contains Credentials"]),

        int(features["Has Dangerous File Extension"]),

        int(features["Has Fragment"]),

        features["Query Length"],

        features["Suspicious Words"],

        features["Login Keywords"]
    ]]

    prediction = int(model.predict(data)[0])

    # --------------------------------------------------
    # Strong phishing indicators
    # --------------------------------------------------

    strong_indicators = 0

    if features["Has IP Address"]:
        strong_indicators += 2

    if features["Has @ Symbol"]:
        strong_indicators += 2

    if features["Has Punycode"]:
        strong_indicators += 2

    if features["Is URL Shortener"]:
        strong_indicators += 1

    if features["Has Suspicious TLD"]:
        strong_indicators += 1

    if features["Contains Credentials"]:
        strong_indicators += 3

    if features["Has Dangerous File Extension"]:
        strong_indicators += 2

    if features["Has Unusual Port"]:
        strong_indicators += 1

    if features["Has URL Encoding"] and features["Number of Encoded Characters"] >= 3:
        strong_indicators += 1

    if features["Number of Subdomains"] >= 4:
        strong_indicators += 1

    if features["Suspicious Words"] >= 3:
        strong_indicators += 1

    # --------------------------------------------------
    # Final decision
    # --------------------------------------------------

    # Model says phishing BUT there are no strong
    # phishing indicators -> avoid aggressive false positive
    if prediction == 1 and strong_indicators < 2:
        return "🟩 Safe Website"

    # Model says phishing AND strong indicators exist
    if prediction == 1 and strong_indicators >= 2:
        return "⚠️ Phishing Website"

    return "🟩 Safe Website"