def ask_question(question, alert_context):

    question = question.lower()

    if "why" in question:
        return "This alert was flagged because suspicious activity was detected."

    if "what should i do" in question:
        return "Block the IP and investigate the affected account."

    return "Further investigation is recommended."
