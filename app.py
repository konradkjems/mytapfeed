from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})  # Tillader alle anmodninger til /api/

# Konfiguration af database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///standere.db'  # Filbaseret SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Deaktiverer ændringssporingen

# Initialiser SQLAlchemy
db = SQLAlchemy(app)

# Definer database-modellen for standere
class Stander(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    standerID = db.Column(db.String(50), nullable=False, unique=True)  # Stander ID
    destination_url = db.Column(db.String(200), nullable=False)  # Destination URL som Standeren peger på

    def __repr__(self):
        return f"<Stander {self.standerID} -> {self.destination_url}>"

# Opret tabeller i databasen
with app.app_context():
    db.create_all()

@app.route('/api/data', methods=['GET'])
def get_data():
    # Hent query-parametre fra URL'en
    standerID = request.args.get('standerID', 'default_standerID')

    # Tjek om standeren findes i databasen
    stander = Stander.query.filter_by(standerID=standerID).first()

    if stander:
        return jsonify({
            "message": "Stander found",
            "status": "success",
            "standerID": stander.standerID,
            "destination_url": stander.destination_url
        })
    else:
        return jsonify({
            "message": "Stander not found",
            "status": "not found",
            "standerID": standerID
        })

@app.route('/<standerID>', methods=['GET'])
def redirect_stander(standerID):
    # Find destination URL baseret på standerID
    stander = Stander.query.filter_by(standerID=standerID).first()

    if stander:
        # Omdiriger brugeren til den gemte destination URL
        return redirect(stander.destination_url)
    else:
        return jsonify({
            "message": "Stander not found",
            "status": "not found",
            "standerID": standerID
        })

@app.route('/api/add_stander', methods=['POST'])
def add_stander():
    # Få data fra POST-anmodningen
    data = request.get_json()
    standerID = data.get('standerID')
    destination_url = data.get('destination_url')

    # Opret en ny Stander-post
    new_stander = Stander(standerID=standerID, destination_url=destination_url)
    db.session.add(new_stander)
    db.session.commit()

    return jsonify({
        "message": "Stander added successfully",
        "status": "success",
        "standerID": standerID,
        "destination_url": destination_url
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
