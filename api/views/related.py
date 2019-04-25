if __name__ == "__main__":
    from views_comm import *
else:
    from .views_comm import * # .views=views.py, views=this folder


# Load Report Database
rcoll = coll_or_fs('report')

def get_related(**kwargs):
    result_bundle = []
    
    # Find matching object
    obj_typ = kwargs['obj_typ']
    if obj_typ in ['ipv4-addr', 'url']:
        obj_val = kwargs['obj_val']
        query = { "$and" : [ {"objects.0.value" : obj_val},
                             {"objects.0.type" : obj_typ} ]}
    else: return None   
        
    obj = rcoll.find_one(query, _PROJECTION)
    if not obj: return None
    
    obj = stix2.parse(obj, allow_custom=True)
    result_bundle.append(obj)

    # Find all relations
    query = {"$and" : [{"$or" : [{"source_ref" : obj["id"]},{"target_ref" : obj["id"]}]},
            {"type" : "relationship"}, {"relationship_type" : {"$ne" : "filtered-from"}}]}
    all_rels = rcoll.find(query, _PROJECTION)

    # Find all related objects
    for rel in all_rels:
        if rel["source_ref"] == obj["id"] :
            rel_objid = rel["target_ref"]
        else: rel_objid = rel["source_ref"]
        query = {"id" : rel_objid}
        rel_obj = rcoll.find_one(query, _PROJECTION)

        relation_obj = stix2.parse(rel)
        related_obj = stix2.parse(rel_obj, allow_custom = True)
        result_bundle.extend((relation_obj, related_obj))

    result_bundle = stix2.Bundle(result_bundle)
    return json.loads(result_bundle.serialize())


rparser = reqparse.RequestParser()
rparser.add_argument('ipv4-addr')
rparser.add_argument('url')

class Related(Resource):
##    decorators = []

    @jwt_required
    def post(self):
        example = { "ipv4-addr" : "104.168.138.60" }
        req = rparser.parse_args()

        valid_obj_typ = ['ipv4-addr', 'url']
        req_keys = req.keys()

        count = 0
        for ot in valid_obj_typ:
            ov = req[ot]
            if ov:
                obj_typ = ot
                obj_val = ov 
                count += 1
        if count < 1: return ({'message': 'Input valid attribute object, check spelling', 'example':example}, 400)
        elif count > 1: return ({'message' : 'Input one attribute object at a time', 'example':example}, 400)

        obj_val = req[obj_typ]
        r = get_related(obj_typ = obj_typ, obj_val = obj_val)

        if not r:  r = {'message': obj_typ + ' object not found: ' + obj_val}
        return (r, 200)
