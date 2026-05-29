from flask import Flask, render_template_string
import requests

app = Flask(__name__)

BACKEND_URL = "http://127.0.0.1:8000"

HTML = """

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAI Dashboard</title>

    <style>

        *{
            margin:0;
            padding:0;
            box-sizing:border-box;
            font-family:Arial;
        }

        body{
            background:#071226;
            color:white;
        }

        .container{
            display:flex;
            height:100vh;
        }

        /* SIDEBAR */

        .sidebar{
            width:250px;
            background:#101c33;
            padding:30px 20px;
            display:flex;
            flex-direction:column;
            justify-content:space-between;
        }

        .sidebar h1{
            color:#ff6b6b;
            margin-bottom:40px;
        }

        .sidebar ul{
            list-style:none;
        }

        .sidebar ul li{
            padding:15px;
            margin-bottom:10px;
            border-radius:10px;
            cursor:pointer;
            color:#cbd5e1;
            transition:0.3s;
        }

        .sidebar ul li:hover{
            background:#24344d;
        }

        .sidebar ul li.active{
            background:#24344d;
        }

        .server-status{
            color:#ff7b7b;
            font-size:18px;
        }

        /* MAIN */

        .main{
            flex:1;
            padding:30px;
            overflow-y:auto;
        }

        .topbar{
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:30px;
        }

        .topbar h2{
            font-size:40px;
        }

        .topbar p{
            color:#94a3b8;
            margin-top:10px;
        }

        .topbar button{
            background:#101c33;
            border:none;
            padding:15px 25px;
            color:white;
            border-radius:10px;
            cursor:pointer;
            font-size:16px;
            transition:0.3s;
        }

        .topbar button:hover{
            background:#24344d;
        }

        /* STATS */

        .stats-grid{
            display:grid;
            grid-template-columns:repeat(4,1fr);
            gap:20px;
            margin-bottom:30px;
        }

        .card{
            background:#16233d;
            padding:25px;
            border-radius:15px;
        }

        .card h3{
            margin-bottom:15px;
            color:#94a3b8;
            font-size:22px;
        }

        .card p{
            font-size:45px;
            font-weight:bold;
        }

        .low-color{
            color:#4ade80;
        }

        .medium-color{
            color:#facc15;
        }

        .high-color{
            color:#fb923c;
        }

        .critical-color{
            color:#f87171;
        }

        /* CONTENT */

        .content-grid{
            display:grid;
            grid-template-columns:300px 1fr;
            gap:20px;
            margin-bottom:30px;
        }

        .severity-item{
            display:flex;
            justify-content:space-between;
            margin-bottom:20px;
            font-size:20px;
        }

        /* ALERTS */

        .alerts-box{
            max-height:420px;
            overflow-y:auto;
        }

        .alert-item{
            background:#0f172a;
            padding:15px;
            border-radius:10px;
            margin-bottom:15px;
            display:flex;
            justify-content:space-between;
            align-items:center;
        }

        .alert-left{
            width:80%;
        }

        .badge{
            padding:8px 15px;
            border-radius:20px;
            font-size:14px;
            font-weight:bold;
        }

        .low{
            border-left:5px solid #4ade80;
        }

        .medium{
            border-left:5px solid #facc15;
        }

        .high{
            border-left:5px solid #fb923c;
        }

        .critical{
            border-left:5px solid #f87171;
        }

        .badge.low{
            background:#14532d;
            border:none;
        }

        .badge.medium{
            background:#713f12;
            border:none;
        }

        .badge.high{
            background:#9a3412;
            border:none;
        }

        .badge.critical{
            background:#7f1d1d;
            border:none;
        }

        /* INCIDENTS */

        .incident-grid{
            display:grid;
            grid-template-columns:repeat(3,1fr);
            gap:20px;
        }

        .incident-card{
            background:#16233d;
            padding:20px;
            border-radius:15px;
        }

        .incident-card h3{
            margin-bottom:20px;
        }

        .timeline{
            display:flex;
            align-items:center;
            gap:10px;
            margin-top:20px;
            flex-wrap:wrap;
        }

        .stage{
            background:#7c2d12;
            padding:10px 15px;
            border-radius:20px;
            font-size:14px;
        }

        /* CHAT */

        .chat-box{
            margin-top:30px;
        }

        .chat-area{
            background:#16233d;
            padding:20px;
            border-radius:15px;
        }

        .chat-area input{
            width:80%;
            padding:15px;
            border:none;
            border-radius:10px;
            margin-top:15px;
            background:#0f172a;
            color:white;
        }

        .chat-area button{
            padding:15px;
            border:none;
            border-radius:10px;
            background:#24344d;
            color:white;
            cursor:pointer;
        }

        #chatResponse{
            margin-top:20px;
            color:#cbd5e1;
            line-height:1.6;
        }

    </style>

</head>

<body>

<div class="container">

    <!-- SIDEBAR -->

    <div class="sidebar">

        <div>

            <h1>🛡 SentinelAI</h1>

            <ul>
                <li class="active">Dashboard</li>
                <li>Alert Feed</li>
                <li>Incidents</li>
                <li>AI Chat</li>
                <li>Reports</li>
            </ul>

        </div>

        <div class="server-status">
            ● Server Live
        </div>

    </div>

    <!-- MAIN -->

    <div class="main">

        <div class="topbar">

            <div>
                <h2>Dashboard</h2>
                <p>AI Powered SOC Monitoring</p>
            </div>

            <button onclick="simulateAttack()">
                🚨 Simulate Attack
            </button>

        </div>

        <!-- STATS -->

        <div class="stats-grid">

            <div class="card">
                <h3>Low</h3>
                <p class="low-color" id="lowCount">0</p>
            </div>

            <div class="card">
                <h3>Medium</h3>
                <p class="medium-color" id="mediumCount">0</p>
            </div>

            <div class="card">
                <h3>High</h3>
                <p class="high-color" id="highCount">0</p>
            </div>

            <div class="card">
                <h3>Critical</h3>
                <p class="critical-color" id="criticalCount">0</p>
            </div>

        </div>

        <!-- ALERTS -->

        <div class="content-grid">

            <div class="card">

                <h3>Alert Distribution</h3>

                <div class="severity-item">
                    Critical
                    <span id="criticalSide">0</span>
                </div>

                <div class="severity-item">
                    High
                    <span id="highSide">0</span>
                </div>

                <div class="severity-item">
                    Medium
                    <span id="mediumSide">0</span>
                </div>

                <div class="severity-item">
                    Low
                    <span id="lowSide">0</span>
                </div>

            </div>

            <div class="card alerts-box">

                <h3>Recent Alerts</h3>

                <div id="alertsContainer">

                </div>

            </div>

        </div>

        <!-- INCIDENTS -->

        <div class="incident-grid">

            <div class="incident-card">

                <h3>Brute Force Campaign</h3>

                <div class="timeline">
                    <div class="stage">Initial Access</div>
                    →
                    <div class="stage">Escalation</div>
                    →
                    <div class="stage">Impact</div>
                </div>

            </div>

            <div class="incident-card">

                <h3>Port Scan Intrusion</h3>

                <div class="timeline">
                    <div class="stage">Recon</div>
                    →
                    <div class="stage">Exploit</div>
                </div>

            </div>

            <div class="incident-card">

                <h3>Privilege Escalation</h3>

                <div class="timeline">
                    <div class="stage">Privilege Gain</div>
                    →
                    <div class="stage">Impact</div>
                </div>

            </div>

        </div>

        <!-- AI CHAT -->

        <div class="chat-box">

            <div class="chat-area">

                <h3>AI Security Assistant</h3>

                <input type="text" id="questionInput"
                placeholder="Ask something like: Why was this flagged?">

                <button onclick="askAI()">
                    Ask AI
                </button>

                <div id="chatResponse"></div>

            </div>

        </div>

    </div>

</div>

<script>

const API_URL = "http://127.0.0.1:8000";

async function loadStats(){

    try{

        const response = await fetch(`${API_URL}/stats`);
        const data = await response.json();

        document.getElementById("lowCount").innerText = data.low;
        document.getElementById("mediumCount").innerText = data.medium;
        document.getElementById("highCount").innerText = data.high;
        document.getElementById("criticalCount").innerText = data.critical;

        document.getElementById("lowSide").innerText = data.low;
        document.getElementById("mediumSide").innerText = data.medium;
        document.getElementById("highSide").innerText = data.high;
        document.getElementById("criticalSide").innerText = data.critical;

    }catch(err){
        console.log(err);
    }

}

async function loadAlerts(){

    try{

        const response = await fetch(`${API_URL}/alerts`);
        const alerts = await response.json();

        const container =
        document.getElementById("alertsContainer");

        container.innerHTML = "";

        alerts.reverse().slice(0,10).forEach(alert => {

            const severity =
            alert.severity.toLowerCase();

            const div = document.createElement("div");

            div.className = `alert-item ${severity}`;

            div.innerHTML = `

                <div class="alert-left">
                    ${alert.log_text}
                </div>

                <div class="badge ${severity}">
                    ${alert.severity}
                </div>

            `;

            container.appendChild(div);

        });

    }catch(err){
        console.log(err);
    }

}

async function simulateAttack(){

    try{

        await fetch(`${API_URL}/simulate`, {
            method:"POST"
        });

        alert("Attack Simulation Started");

        setTimeout(() => {
            loadStats();
            loadAlerts();
        }, 2000);

    }catch(err){
        console.log(err);
    }

}

async function askAI(){

    const question =
    document.getElementById("questionInput").value;

    if(question === ""){
        return;
    }

    try{

        const response = await fetch(`${API_URL}/ask`, {

            method:"POST",

            headers:{
                "Content-Type":"application/json"
            },

            body:JSON.stringify({
                question:question,
                alert_id:1
            })

        });

        const data = await response.json();

        document.getElementById("chatResponse")
        .innerHTML = `
            <strong>AI Response:</strong><br><br>
            ${data.answer}
        `;

    }catch(err){

        document.getElementById("chatResponse")
        .innerHTML = "AI service unavailable.";

    }

}

loadStats();
loadAlerts();

setInterval(() => {
    loadStats();
    loadAlerts();
}, 5000);

</script>

</body>
</html>

"""

@app.route("/")
def dashboard():
    return render_template_string(HTML)

if __name__ == "__main__":
    app.run(debug=True, port=3000)