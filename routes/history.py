from flask import Blueprint, render_template, jsonify
from datetime import datetime
from model import History
from utils import db

history_blueprint = Blueprint('history', __name__)

def get_relative_time(timestamp):
    now = datetime.now()
    delta = now - timestamp

    if delta.days > 1:
        return f"{delta.days} days ago"
    elif delta.days == 1:
        return "1 day ago"
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        return f"{hours} hours ago" if hours > 1 else "1 hour ago"
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        return f"{minutes} minutes ago" if minutes > 1 else "1 minute ago"
    else:
        return "just now"


@history_blueprint.route('/history')
def show_history():
    try:
        history_data = History.query.order_by(History.timestamp.desc()).all()

        for i in history_data:
            i.relative_time = get_relative_time(i.timestamp)

        return render_template('history.html', history=history_data)
    
    except Exception as e:
        return jsonify({
            "status": "failed",
            "message": f"Error: {e}",
            "timestamp": datetime.now()
        }), 500
