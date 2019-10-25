import sys
sys.path.append("..")

from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from database import db

app = Flask(__name__)
api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my-secret-string'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

@app.before_first_request
def create_tables():
    db.create_all()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)

import views, models, resources

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')

api.add_resource(views.AttributeSummary, '/api/v1.0/summary/attribute')
api.add_resource(views.AttributeValueSummary, '/api/v1.0/summary/attribute/<att_type>')
api.add_resource(views.EventSummary, '/api/v1.0/summary/event')


api.add_resource(views.EventFeatures,'/api/v1.0/event/features')

api.add_resource(views.Raw, '/api/v1.0/raw')

api.add_resource(views.Related, '/api/v1.0/related')
api.add_resource(views.RelatedAttribute, '/api/v1.0/related/attribute')
api.add_resource(views.RelatedAttributeSummary, '/api/v1.0/related/attribute/summary')
api.add_resource(views.RelatedAttributeSummaryByEvent, '/api/v1.0/related/attribute/summary/byevent')
api.add_resource(views.RelatedEventSummary, '/api/v1.0/related/event/summary')

api.add_resource(views.Count,'/api/v1.0/count')
api.add_resource(views.CountByOrgSummary, '/api/v1.0/org')
api.add_resource(views.CountByOrgCategorySummary, '/api/v1.0/orgsec')



if __name__=='__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
