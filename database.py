from pymongo import MongoClient

# Conexión a MongoDB con autenticación
client = MongoClient("mongodb://civicfix_user:civicfix123@127.0.0.1:27017/reportes_db")

# Selecciona la base de datos
db = client["reportes_db"]

# Selecciona las colecciones
reportes_collection = db["reportes"]
usuarios_collection = db["usuarios"]
categorias_collection = db["categorias"]
comentarios_collection = db["comentarios"]
votos_collection = db["votos"]