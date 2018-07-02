from restapi import app,bcrypt,db
from flask import request,jsonify,make_response
from restapi.models import User
import uuid
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from functools import wraps

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        s = Serializer(app.config['SECRET_KEY'])
        try: 
            public_id = s.loads(token)['public_id']
            
            #data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=public_id).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/users",methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})

    users = User.query.all()
    output =[]

    for user in users:
        user_data ={}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        output.append(user_data)
    return jsonify({'users':output})

@app.route("/users/<string:public_id>",methods=['GET'])
@token_required
def get_single_user(current_user,public_id):

    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})


    user = User.query.filter_by(public_id=public_id).first()

    if user is None:
        return jsonify({'message':'No User Found'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user':user_data})

@app.route("/users",methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})

    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    user = User(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message':'User Added Successfully!'})

@app.route("/users/<string:public_id>",methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})


    user = User.query.filter_by(public_id=public_id).first()

    if user is None:
        return jsonify({'message':'No User Found'})
    
    user.admin = True
    db.session.commit()

    return jsonify({'message':'User has been promoted'})

@app.route("/users/<string:public_id>",methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})

        
    user = User.query.filter_by(public_id=public_id).first()

    if user is None:
        return jsonify({'message':'No User Found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message':'User has been deleted'})


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if bcrypt.check_password_hash(user.password, auth.password):

        s = Serializer(app.config['SECRET_KEY'],1800)

        token = s.dumps({'public_id': user.public_id}).decode('utf-8')
        #token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
