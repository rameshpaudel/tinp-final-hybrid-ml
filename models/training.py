import datetime
from utils.main import db

'''Displays the scan history of each files and their result'''
class Training(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    model_file = db.Column(db.String(150),nullable=True)
    dataset_for = db.Column(db.String(10), nullable=True)
    classification_report = db.Column(db.JSON, nullable=True)
    training_results=db.Column(db.JSON,nullable=True)
    results=db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())
    