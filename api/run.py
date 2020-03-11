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


# api.add_resource(GOManagement.CreateGroup, '/group/create')
# api.add_resource(GOManagement.CreateOrg  , '/org/create')
# api.add_resource(GOManagement.DeleteGroup, '/group/delete')
# api.add_resource(GOManagement.DeleteOrg  , '/org/delete')
# api.add_resource(GOManagement.ClearGroup , '/group/clear')
# api.add_resource(GOManagement.ClearOrg   , '/org/clear')


# api.add_resource(GOManagement.GroupAddUser, '/group/add/user')
# api.add_resource(GOManagement.GroupAddOrg , '/group/add/org')
# api.add_resource(GOManagement.OrgAddUser  , '/org/add/user')

# api.add_resource(GOManagement.GroupRemoveUser, '/group/remove/user')
# api.add_resource(GOManagement.GroupRemoveOrg , '/group/remove/org')
# api.add_resource(GOManagement.GroupRemoveUorO, '/group/remove/')
# api.add_resource(GOManagement.OrgRemoveUser  , '/org/remove/user')

# api.add_resource(GOManagement.GroupsOwned, '/group/owned')
# api.add_resource(GOManagement.OrgsOwned  , '/org/owned')

# api.add_resource(GOManagement.GroupListUsers  , '/group/list/only/users')
# api.add_resource(GOManagement.GroupListOrgs   , '/group/list/only/orgs')
# api.add_resource(GOManagement.GroupListAllUers, '/group/list/all') # will recurse
# api.add_resource(GOManagement.OrgListUsers    , '/org/list/users')



api.add_resource(views.AttributeSummary, '/api/v1.0/summary/attribute')
api.add_resource(views.AttributeValueSummary, '/api/v1.0/summary/attribute/<att_type>')
api.add_resource(views.EventSummary, '/api/v1.0/summary/event')


api.add_resource(views.EventFeatures,'/api/v1.0/event/features')

api.add_resource(views.Raw, '/api/v1.0/raw')

api.add_resource(views.Related, '/api/v1.0/related')
api.add_resource(views.RelatedAttribute, '/api/v1.0/related/attribute')
api.add_resource(views.RelatedEvent, '/api/v1.0/related/event')
api.add_resource(views.RelatedAttributeSummary, '/api/v1.0/related/attribute/summary')
api.add_resource(views.RelatedAttributeSummaryByEvent, '/api/v1.0/related/attribute/summary/byevent')

api.add_resource(views.Count,'/api/v1.0/count')
api.add_resource(views.CountMalicious,'/api/v1.0/count/malicious')
api.add_resource(views.CountByEventAtt,'/api/v1.0/count/byevent/byatt')
api.add_resource(views.CountByOrgSummary, '/api/v1.0/count/byorg')
api.add_resource(views.CountMaliciuosByOrgSummary, '/api/v1.0/count/malicious/byorg')
api.add_resource(views.CountByOrgCategorySummary, '/api/v1.0/count/byorgsec')
api.add_resource(views.CountMaliciousByOrgCategorySummary, '/api/v1.0/count/malicious/byorgsec')



if __name__=='__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
