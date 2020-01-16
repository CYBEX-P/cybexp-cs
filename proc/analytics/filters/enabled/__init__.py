import pkgutil, logging

imported_filters = list()

__path__ = pkgutil.extend_path(__path__, __name__)
for importer, modname, ispkg in pkgutil.walk_packages(path=__path__, prefix=__name__+'.'):
   # print(importer,modname, ispkg)
   # print("importing", modname)
   try:
      __import__(modname)
      imported_filters.append(modname)
   except:
      logging.error(f"proc.analytics.filters.enabled.__init__: Filter {modname} could not be imported", exc_info=True)

