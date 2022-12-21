from flask import Flask, Response, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_restful import Api, Resource
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import datetime
from os import environ

# load_dotenv()

app = Flask(__name__)
db = SQLAlchemy(app)
ma = Marshmallow(app)
api = Api(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('SQLALCHEMY_DATABASE_URI')
app.config['JWT_SECRET_KEY'] = environ.get('JWT_SECRET_KEY')
app.app_context().push()

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Car(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50))
    model = db.Column(db.String(50))
    year = db.Column(db.String(4))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'{self.year} {self.make} {self.model}'


# Schemas
class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "email")

class CarSchema(ma.Schema):
    class Meta:
        fields = ("id", "make", "model", "year", "user_id")


car_schema = CarSchema()
cars_schema = CarSchema(many=True)
user_schema = UserSchema()

# Resources (Class-based view functions)
class CarListResource(Resource):
    def get(self):
        cars = Car.query.all()
        return cars_schema.dump(cars)

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        new_car = Car(
            make=request.json['make'],
            model=request.json['model'],
            year=request.json['year'],
            user_id=user_id
        )
        db.session.add(new_car)
        db.session.commit()
        return car_schema.dump(new_car)


class CarResource(Resource):
    def get(self, car_id):
        car = Car.query.get_or_404(car_id)
        return car_schema.dump(car)

    @jwt_required()
    def patch(self, car_id):
        car = Car.query.get_or_404(car_id)

        if 'make' in request.json:
            car.make = request.json['make']
        if 'model' in request.json:
            car.model = request.json['model']
        if 'year' in request.json:
            car.year = request.json['year']

        db.session.commit()
        return car_schema.dump(car)

    @jwt_required()
    def delete(self, post_id):
        post = Car.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()
        return '', 204

    
class UserCarResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user_cars = Car.query.filter_by(user_id=user_id)
        return cars_schema.dump(user_cars), 200

#Auth Resources
class RegisterResource(Resource):
    def post(self):
        body = request.get_json()
        new_user = User(**body)
        new_user.hash_password()
        db.session.add(new_user)
        db.session.commit()
        return user_schema.dump(new_user), 201

class LoginResource(Resource):
    def post(self):
        body = request.get_json()
        user = db.one_or_404(
            db.select(User).filter_by(username=body.get('username')),
            description=f"No user with that username."
        )
        authorized = user.check_password(body.get('password'))
        if not authorized:
            return {'error': 'Username or password invalid'}, 401
        expires = datetime.timedelta(days=7)
        access_token = create_access_token(identity=str(user.id), expires_delta=expires)
        return {'access': access_token}, 200

# Creating routes
api.add_resource(CarListResource, '/api/cars')
api.add_resource(CarResource, '/api/cars/<int:car_id>')
api.add_resource(RegisterResource, '/api/auth/signup')
api.add_resource(LoginResource, '/api/auth/login')
api.add_resource(UserCarResource, '/api/user_cars')

if __name__ == '__main__':
    app.run(debug=True)
