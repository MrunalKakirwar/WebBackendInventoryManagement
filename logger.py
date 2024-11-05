from datetime import datetime
from utils import db
from model import History

def log_action(user_id, item_id, action_type):
    history_entry = History(
        user_id=user_id,
        item_id=item_id,
        action_type=action_type,
        timestamp=datetime.now()
    )
    db.session.add(history_entry)
    db.session.commit()
