if __name__ == "__main__":
    from views_comm import *
else:
    from .views_comm import * # .views=views.py, views=this folder


# Load Report Database
rcoll = coll_or_fs('report')

def get_related(obj_typ, obj_val, **kwargs):
    result_bundle = []

    query = { "$and" : [ {"objects.0.type" : obj_typ} ]}
    
    # Take care of special structures
    if obj_typ == 'file': query["$and"].append({"objects.0.hashes.SHA-256" : obj_val} )
    else: query["$and"].append({"objects.0.value" : obj_val} )
        
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
for va in _VALID_ATT: rparser.add_argument(va)

class Related(Report):
    def __init__(self):
        super().__init__({ "ipv4-addr" : "104.168.138.60" })

    @jwt_required
    def post(self):
        obj_typ, obj_val = super().post(rparser)
        
        # Get Related
        r = get_related(obj_typ, obj_val)

        if not r:  r = {'message': obj_typ + ' object not found: ' + obj_val}
        return (r, 200)    

