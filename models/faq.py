import datetime
from utils.main import db

class Faq(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(150))
    answer = db.Column(db.String(250))
    order =db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())