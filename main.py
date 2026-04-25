from flask import Flask, request, jsonify, render_template_string
import re
from datetime import datetime
from google.cloud import bigquery

app = Flask(__name__)

# ---------------- CONFIG ----------------
bq_client = bigquery.Client()
table_id = "project-b3a1d3db-dbdc-4c1a-93d.agentic_logs.transactions"

# ---------------- SMART RISK LOGIC ----------------
SAFE_DOMAINS = ["google.com", "youtube.com", "amazon.in", "microsoft.com"]
SUSPICIOUS_KEYWORDS = ["login", "secure", "verify", "update", "bank", "free", "bonus"]
MALICIOUS_KEYWORDS = ["malware", "phishing", "hack", "attack", "trojan", "virus"]

def get_risk(value, decision):
    v = value.lower()

    # HIGH
    if any(k in v for k in MALICIOUS_KEYWORDS):
        return "HIGH"

    # MEDIUM
    if any(k in v for k in SUSPICIOUS_KEYWORDS):
        return "MEDIUM"

    # SAFE domains
    if v in SAFE_DOMAINS:
        return "LOW"

    # IP logic
    if decision == "ip":
        if v.startswith(("192.", "10.", "172.")):
            return "LOW"
        return "MEDIUM"

    # Domain logic (🔥 improved)
    if decision == "domain":
        if v in SAFE_DOMAINS:
            return "LOW"
        return "MEDIUM"

    return "LOW"

# ---------------- ANALYZE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    inp = request.json.get("input", "")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", inp):
        decision = "ip"
        api = "abuseipdb"

    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", inp):
        decision = "domain"
        api = "virustotal"

    else:
        decision = "invalid"
        api = "none"

    risk = get_risk(inp, decision)

    # log
    bq_client.insert_rows_json(table_id, [{
        "input": inp,
        "decision": decision,
        "api_used": api,
        "cost_usdc": 0.001,
        "timestamp": datetime.utcnow().isoformat()
    }])

    return jsonify({"type": decision, "api": api, "risk": risk})

# ---------------- LOGS ----------------
@app.route("/logs")
def logs():
    rows = bq_client.query(f"""
        SELECT input, decision, api_used, cost_usdc, timestamp
        FROM `{table_id}`
        ORDER BY timestamp DESC LIMIT 200
    """).result()

    return jsonify([
        {
            "input": r.input,
            "decision": r.decision,
            "api_used": r.api_used,
            "cost_usdc": r.cost_usdc,
            "timestamp": str(r.timestamp)
        }
        for r in rows
    ])

# ---------------- STATS ----------------
@app.route("/stats")
def stats():
    rows = bq_client.query(f"""
        SELECT api_used, COUNT(*) c
        FROM `{table_id}`
        GROUP BY api_used
    """).result()

    return jsonify({
        "labels": [r.api_used for r in rows],
        "values": [r.c for r in rows]
    })

# ---------------- KPI ----------------
@app.route("/kpi")
def kpi():
    r = list(bq_client.query(f"""
        SELECT COUNT(*) total, SUM(cost_usdc) cost
        FROM `{table_id}`
    """).result())[0]

    return jsonify({
        "total": r.total,
        "cost": float(r.cost or 0)
    })

# ---------------- ALERTS (SHOW ALL) ----------------
@app.route("/alerts")
def alerts():
    rows = bq_client.query(f"""
        SELECT input, decision
        FROM `{table_id}`
        ORDER BY timestamp DESC LIMIT 20
    """).result()

    data = []
    for r in rows:
        risk = get_risk(r.input, r.decision)

        data.append({
            "input": r.input,
            "risk": risk
        })

    return jsonify(data)

# ---------------- UI ----------------
@app.route("/")
def home():
    return render_template_string("""
<html>
<head>
<title>SOC Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {background:#0b1220;color:white;font-family:Arial;margin:0}
.container {width:95%;margin:auto}

h1{text-align:center}

input{padding:10px;width:250px;border-radius:5px;border:none}
button{padding:10px;background:#38bdf8;border:none;border-radius:5px}

.kpi{display:flex;gap:10px;margin:15px 0}
.card{flex:1;background:#1e293b;padding:15px;border-radius:10px;text-align:center}

.alert{padding:10px;margin:6px;border-radius:8px;font-weight:bold}
.high{background:#7f1d1d}
.medium{background:#78350f}
.low{background:#064e3b}

table{width:100%;border-collapse:collapse}
th{background:#1e293b}
td,th{padding:10px;border-bottom:1px solid #334155}
tr:hover{background:#1e293b}

.badge{padding:4px 8px;border-radius:6px}
.ip{background:#0ea5e9}
.domain{background:#22c55e}
.invalid{background:#64748b}

.pagination{text-align:center;margin:10px}
</style>
</head>

<body>

<h1>🚀 Agentic SOC Dashboard</h1>

<div class="container">

<!-- INPUT -->
<div style="text-align:center">
<input id="input" placeholder="Search IP / Domain">
<button onclick="analyze()">Analyze</button>
</div>

<div id="result" style="text-align:center;margin:10px"></div>

<!-- KPI -->
<div class="kpi">
<div class="card">Total<br><span id="total"></span></div>
<div class="card">Cost<br><span id="cost"></span></div>
</div>

<!-- ALERTS -->
<h3>🚨 Live Alerts</h3>
<div id="alerts"></div>

<!-- CHART -->
<canvas id="chart"></canvas>

<!-- TABLE -->
<h3>Transactions</h3>
<table>
<thead>
<tr><th>Input</th><th>Decision</th><th>API</th><th>Cost</th><th>Time</th></tr>
</thead>
<tbody id="table"></tbody>
</table>

<div class="pagination">
<button onclick="prev()">Prev</button>
<span id="page"></span>
<button onclick="next()">Next</button>
</div>

</div>

<script>
let data=[],page=1,size=15

async function analyze(){
 let val=input.value
 let r=await fetch("/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({input:val})})
 let d=await r.json()
 result.innerHTML=`<div class="alert ${d.risk.toLowerCase()}">${d.type} | ${d.api} | ${d.risk}</div>`
 loadAll()
}

async function loadAll(){
 loadLogs();loadChart();loadKPI();loadAlerts()
}

async function loadLogs(){
 let r=await fetch("/logs")
 data=await r.json()
 render()
}

function render(){
 let rows=""
 data.slice((page-1)*size,page*size).forEach(x=>{
  rows+=`<tr>
  <td>${x.input}</td>
  <td><span class="badge ${x.decision}">${x.decision}</span></td>
  <td>${x.api_used}</td>
  <td>${x.cost_usdc}</td>
  <td>${x.timestamp}</td>
  </tr>`
 })
 table.innerHTML=rows
 page.innerText="Page "+page
}

function next(){if(page*size<data.length){page++;render()}}
function prev(){if(page>1){page--;render()}}

async function loadChart(){
 let r=await fetch("/stats")
 let d=await r.json()
 if(window.chart)chart.destroy()
 chart=new Chart(document.getElementById("chart"),{
  type:"bar",
  data:{labels:d.labels,datasets:[{data:d.values,label:"API Usage"}]}
 })
}

async function loadKPI(){
 let r=await fetch("/kpi")
 let d=await r.json()
 total.innerText=d.total
 cost.innerText=d.cost.toFixed(3)
}

async function loadAlerts(){
 let r=await fetch("/alerts")
 let d=await r.json()
 let html=""
 d.forEach(a=>{
  let icon = a.risk==="HIGH"?"🔴":a.risk==="MEDIUM"?"🟠":"🟢"
  html+=`<div class="alert ${a.risk.toLowerCase()}">${icon} ${a.input} - ${a.risk}</div>`
 })
 alerts.innerHTML=html
}

loadAll()
setInterval(loadAll,5000)
</script>

</body>
</html>
""")

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
