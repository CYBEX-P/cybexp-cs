from database import db
from passlib.hash import pbkdf2_sha256 as sha256
#from flask_sqlalchemy import desc

class UserModel(db.Model):
    __tablename__ = 'users'

    tid = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)
    orgid = db.Column(db.String(36), nullable = False)
    isadmin = db.Column(db.Boolean, default=False, nullable=False)
    userid = db.Column(db.String(36), primary_key = True, nullable = False)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()
    
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password,
                'orgid': x.orgid,
                'isadmin': x.isadmin,
                'userid': x.userid
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)
    
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)



class GroupModel(db.Model):
    __tablename__ = 'groups'

    tid = db.Column(db.Integer, primary_key = True)
    groupName = db.Column(db.String(120), default="",nullable = False)
    groupid = db.Column(db.String(36), unique = True, nullable = False)
    owner_userid = db.Column(db.String(36), nullable = False)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def find_by_groupid(cls, groupid):
        return cls.query.filter_by(groupid = groupid).first()
    
    @classmethod
    def return_all_groups(cls):
        groups = list()
        for entry in GroupModel.query.all():
            groups.append(entry.groupid)
        return groups

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'tid': x.tid,
                'groupName': x.groupName,
                'groupid': x.groupid,
                'owner_userid': x.owner_userid
            }

        return {'groups': list(map(lambda x: to_json(x), GroupModel.query.all()))}
    @classmethod
    def return_all_AL_raw(cls):
        def to_json(gid):
            return {
                'groupid': gid,
                "access_list": GALModel.return_group_AL_raw(gid) 
            }
            # someselect.order_by(desc(table1.mycol))
            # entities = MyEntity.query.order_by(desc(MyEntity.time)).limit(3).all()    

        return {'groups': list(map(lambda x: to_json(x), cls.return_all_groups()))}

    @classmethod
    def return_all_AL_all(cls):
        pass
        # same as all AL raw but allso goes one level deep
        def to_json(gid):
            return {
                'groupid': gid,
                "access_list": cls.return_group_AL_expanded(gid) 
            }

        return {'groups': list(map(lambda x: to_json(x), cls.return_all_groups()))}

    @classmethod
    def return_group_AL_expanded(cls, groupid):
        userAL = list()
        gal = GALModel.return_group_AL_raw(gid)

        for entry in gal:
            if entry["id_type"] == GALModel.USER_TYPE:
                userAL.append(entry["allowid"])
            elif entry["id_type"] == GALModel.ORG_TYPE:
                oml = OMLModel.return_org_memb(entry["allowid"])
                userAL.extend(oml)
        return userAL

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @classmethod
    def delete_group(cls, groupid):
        try:
            num_rows_deleted = cls.query.filter_by(groupid=groupid).delete()
            num_rows_deleted_GAL = GALModel.query.filter_by(groupid=groupid).delete()
            db.session.commit()

            return {'message': '{} groups(s) deleted, {} GAL(s) deleted.'.format(num_rows_deleted, num_rows_deleted_GAL)}
        except:
            return {'message': 'Something went wrong'}

        

class GALModel(db.Model):
    __tablename__ = 'gr_allow_list'

    # type definitions, use whenever posible, if more needed change to ints 
    USER_TYPE = False
    ORG_TYPE = True


    tid = db.Column(db.Integer, primary_key = True)
    groupid = db.Column(db.String(36), nullable = False)
    id_type = db.Column(db.Boolean, default=USER_TYPE, nullable=False)
    allowid = db.Column(db.String(36), primary_key = True, nullable = False)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def find_by_groupid(cls, groupid):
        return cls.query.filter_by(groupid = groupid).all()
    
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'tid': x.tid,
                'groupid': x.groupid,
                'id_type': x.id_type,
                'allowid': x.allowid
            }
        return {'GALs': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def return_group_AL_raw(cls, groupid):
        def to_json(x):
            return {"id_type": x.id_type,
                    "allowid": x.allowid
            }
        return [to_json(item) for item in cls.find_by_groupid(groupid)]

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = cls.query.filter_by(groupid=groupid).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @classmethod
    def delete_group(cls, groupid):
        try:
            num_rows_deleted = cls.query.filter_by(groupid=groupid).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @classmethod
    def delete(cls, groupid, idtype, id):
        # delete user from group
        pass




# class OMLModel(db.Model):


# + OMLModel.return_org_memb(oid)