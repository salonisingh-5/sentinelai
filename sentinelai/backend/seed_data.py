from database import SessionLocal
from models import Alert

db = SessionLocal()

sample_alert = Alert(
    log_text="Failed login attempt from 192.168.1.5",
    threat_type="brute_force",
    severity="High",
    explanation="Multiple failed logins detected"
)

db.add(sample_alert)
db.commit()

print("Seed data inserted successfully")