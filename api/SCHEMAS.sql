
users(
   tid INTEGER PRIMARY KEY,
   userid TEXT PRIMARY KEY  NOT NULL UNIQUE,
   username TEXT NOT NULL UNIQUE,
   password TEXT NOT NULL,
   orgid TEXT NOT NULL,
   isadmin INTEGER NOT NULL DEFAULT 0
)



groups(    
   tid INTEGER PRIMARY KEY,
   groupName TEXT NOT NULL DEFAULT '',
   groupid TEXT NOT NULL UNIQUE,
   owner_userid TEXT NOT NULL
)




# type definitions if more needed change to ints 
USER_TYPE = False # 0
ORG_TYPE = True # 1

gr_allow_list(   
   tid INTEGER PRIMARY KEY,
   groupid = TEXT NOT NULL,
   id_type INTEGER NOT NULL,
   allowid TEXT NOT NULL
)



orgs(    
   tid INTEGER PRIMARY KEY,
   orgid TEXT NOT NULL UNIQUE,
   orgName TEXT NOT NULL DEFAULT '',
   owner_userid TEXT NOT NULL
)


org_allow_list(    
   tid INTEGER PRIMARY KEY,
   orgid = TEXT NOT NULL,
   allowid = TEXT NOT NULL
)


