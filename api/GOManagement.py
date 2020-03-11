from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from uuid import UUID, uuid4

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'Username cannot be blank', required = True)
parser.add_argument('password', help = 'Password cannot be blank', required = True)
parser.add_argument('orgid')
parser.add_argument('isadmin', type=bool)


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}

        orgid = data['orgid']
        if orgid:
            try:
                uuid_obj = UUID(orgid, version=4)
            except:
                return {'message': 'orgid is not a valid UUID4. Contact your organization administrator.'}, 422
        else:
            return {'message': 'orgid is not a valid UUID4. Contact your organization administrator.'}, 422

        isadmin = data['isadmin']
        if not isadmin : isadmin = False
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password']),
            orgid = orgid,
            isadmin = data['isadmin'],
            userid = str(uuid4())

        )
        
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        import pdb
        pdb.set_trace()
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class AllUsers(Resource):
##    @jwt_required
    def get(self):
##        cur_user = get_jwt_identity()
##        cur_user = UserModel.find_by_username(cur_user)
##        if not cur_user.isadmin:
##            return {'message': 'Administrative access required'}, 401

        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }








class CreateGroup(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class CreateOrg(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class DeleteGroup(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class DeleteOrg(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class ClearGroup(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class ClearOrg(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupAddUser(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupAddOrg(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class OrgAddUser(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupRemoveUser(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupRemoveOrg(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupRemoveUorO(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class OrgRemoveUser(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupsOwned(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class OrgsOwned(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupListUsers(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupListOrgs(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class GroupListAllUers(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501
class OrgListUsers(Resource):
    @jwt_required
    def getorpost(self):
        return {'message': 'Not Implemented'}, 501


