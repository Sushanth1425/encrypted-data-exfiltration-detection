from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

@app.route("/")
def dashboard():
    try:
        df = pd.read_csv("results/anomalies.csv")
        alerts = pd.read_csv("results/alerts.csv")
    except:
        df = pd.DataFrame()
        alerts = pd.DataFrame()

    total_flows = len(df)
    total_alerts = len(alerts)

    return render_template(
        "dashboard.html",
        total_flows=total_flows,
        total_alerts=total_alerts,
        alerts=alerts.to_dict(orient="records")
    )

if __name__ == "__main__":
    app.run(debug=True)

