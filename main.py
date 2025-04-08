from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from database import reportes_collection, usuarios_collection, categorias_collection, comentarios_collection, votos_collection
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, messaging
from bson import ObjectId
from typing import Optional, List

# Inicializar Firebase Admin
cred = credentials.Certificate("/home/abram/app/reporte/backend/serviceAccountKey.json")
firebase_admin.initialize_app(cred)

app = FastAPI()

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de JWT
SECRET_KEY = "e8084c8701c7e2bf6b441e2d33efb6b58991f4730a2e4b8cceeeac5ab698616a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Hasheo de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Modelos
class Categoria(BaseModel):
    nombre: str

class Comentario(BaseModel):
    contenido: str
    usuario: Optional[str] = None  # Hacer el campo usuario opcional
    fecha: datetime = datetime.utcnow()

class Voto(BaseModel):
    usuario: Optional[str] = None  # Hacer el campo usuario opcional
    valor: int  # 1 para voto positivo, -1 para voto negativo

class Reporte(BaseModel):
    descripcion: str
    latitud: float
    longitud: float
    foto_url: str | None = None
    estado: str | None = "pendiente"
    categoria_id: str  # Referencia al ID de la categoría
    usuario: str
    comentarios: List[str] = []  # Lista de IDs de comentarios
    votos_positivos: int = 0
    votos_negativos: int = 0

class Usuario(BaseModel):
    email: str
    password: str
    tipo: str = "usuario"

class UsuarioLogin(BaseModel):
    email: str
    password: str

class PushToken(BaseModel):
    token: str

class Notification(BaseModel):
    user_email: str
    title: str
    body: str

class UpdateReporte(BaseModel):
    estado: str | None = None
    categoria_id: str | None = None

# Funciones de utilidad
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        user = usuarios_collection.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        return {"email": user["email"], "tipo": user["tipo"]}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_admin(token: str = Depends(oauth2_scheme)):
    user = await get_current_user(token)
    if user["tipo"] not in ["administrador", "admin"]:
        raise HTTPException(status_code=403, detail="No tienes permisos de administrador")
    return user

# Rutas
@app.get("/")
def read_root():
    return {"message": "¡Backend de Reporte de Servicios Públicos funcionando!"}

# Rutas para Categorías
@app.post("/categorias")
def crear_categoria(categoria: Categoria, current_admin: dict = Depends(get_current_admin)):
    categoria_dict = categoria.dict()
    result = categorias_collection.insert_one(categoria_dict)
    return {"inserted_id": str(result.inserted_id)}

@app.get("/categorias")
def listar_categorias():
    categorias = list(categorias_collection.find({}, {"_id": 0}))
    return categorias

# Rutas para Reportes
@app.post("/reportes")
def crear_reporte(reporte: Reporte, current_user: dict = Depends(get_current_user)):
    if current_user["tipo"] not in ["usuario", "ciudadano"]:
        raise HTTPException(status_code=403, detail="Solo los usuarios pueden crear reportes")
    
    # Verificar que la categoría exista
    categoria = categorias_collection.find_one({"_id": ObjectId(reporte.categoria_id)})
    if not categoria:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    
    reporte_dict = reporte.dict()
    reporte_dict["fecha"] = datetime.utcnow()
    reporte_dict["estado"] = "pendiente"
    reporte_dict["usuario"] = current_user["email"]
    reporte_dict["votos_positivos"] = 0
    reporte_dict["votos_negativos"] = 0
    result = reportes_collection.insert_one(reporte_dict)
    return {"inserted_id": str(result.inserted_id)}

@app.get("/reportes")
def listar_reportes(estado: Optional[str] = None, categoria: Optional[str] = None, usuario: Optional[str] = None):
    query = {}
    if estado:
        query["estado"] = estado
    if categoria:
        query["categoria_id"] = categoria
    if usuario:
        query["usuario"] = usuario
    reportes = list(reportes_collection.find(query))
    for reporte in reportes:
        reporte["_id"] = str(reporte["_id"])
        reporte["categoria_id"] = str(reporte["categoria_id"])
    return reportes

# Rutas para Comentarios
@app.post("/reportes/{reporte_id}/comentarios")
def agregar_comentario(reporte_id: str, comentario: Comentario, current_user: dict = Depends(get_current_user)):
    try:
        reporte_id_obj = ObjectId(reporte_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="ID de reporte inválido")

    reporte = reportes_collection.find_one({"_id": reporte_id_obj})
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    comentario_dict = comentario.dict()
    comentario_dict["usuario"] = current_user["email"]
    comentario_dict["fecha"] = datetime.utcnow()
    result = comentarios_collection.insert_one(comentario_dict)
    comentario_id = str(result.inserted_id)

    # Agregar el comentario al reporte
    reportes_collection.update_one(
        {"_id": reporte_id_obj},
        {"$push": {"comentarios": comentario_id}}
    )
    return {"inserted_id": comentario_id}

@app.get("/reportes/{reporte_id}/comentarios")
def listar_comentarios(reporte_id: str):
    try:
        reporte_id_obj = ObjectId(reporte_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="ID de reporte inválido")

    reporte = reportes_collection.find_one({"_id": reporte_id_obj})
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    comentarios_ids = reporte.get("comentarios", [])
    comentarios = list(comentarios_collection.find({"_id": {"$in": [ObjectId(id) for id in comentarios_ids]}}))
    for comentario in comentarios:
        comentario["_id"] = str(comentario["_id"])
    return comentarios

# Rutas para Votos
@app.post("/reportes/{reporte_id}/votos")
def agregar_voto(reporte_id: str, voto: Voto, current_user: dict = Depends(get_current_user)):
    try:
        reporte_id_obj = ObjectId(reporte_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="ID de reporte inválido")

    reporte = reportes_collection.find_one({"_id": reporte_id_obj})
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    # Verificar si el usuario ya votó
    voto_existente = votos_collection.find_one({"reporte_id": reporte_id, "usuario": current_user["email"]})
    if voto_existente:
        raise HTTPException(status_code=400, detail="Ya has votado por este reporte")

    voto_dict = voto.dict()
    voto_dict["reporte_id"] = reporte_id
    voto_dict["usuario"] = current_user["email"]
    result = votos_collection.insert_one(voto_dict)

    # Actualizar los votos del reporte
    if voto.valor == 1:
        reportes_collection.update_one(
            {"_id": reporte_id_obj},
            {"$inc": {"votos_positivos": 1}}
        )
    elif voto.valor == -1:
        reportes_collection.update_one(
            {"_id": reporte_id_obj},
            {"$inc": {"votos_negativos": 1}}
        )

    return {"inserted_id": str(result.inserted_id)}

@app.get("/reportes/{reporte_id}/votos")
def listar_votos(reporte_id: str):
    try:
        reporte_id_obj = ObjectId(reporte_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="ID de reporte inválido")

    reporte = reportes_collection.find_one({"_id": reporte_id_obj})
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    votos = list(votos_collection.find({"reporte_id": reporte_id}))
    for voto in votos:
        voto["_id"] = str(voto["_id"])
    return votos

@app.post("/register")
def registrar_usuario(usuario: Usuario):
    if usuarios_collection.find_one({"email": usuario.email}):
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    hashed_password = get_password_hash(usuario.password)
    usuario_dict = {"email": usuario.email, "password": hashed_password, "tipo": usuario.tipo, "puntos": 0}
    result = usuarios_collection.insert_one(usuario_dict)
    return {"message": "Usuario registrado", "id": str(result.inserted_id)}

@app.post("/login")
def login_usuario(usuario: UsuarioLogin):
    user = usuarios_collection.find_one({"email": usuario.email})
    if not user or not verify_password(usuario.password, user["password"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": usuario.email, "tipo": user["tipo"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.patch("/reportes/{reporte_id}")
def actualizar_reporte(reporte_id: str, update: UpdateReporte, current_admin: dict = Depends(get_current_admin)):
    try:
        reporte_id_obj = ObjectId(reporte_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="ID de reporte inválido")

    reporte = reportes_collection.find_one({"_id": reporte_id_obj})
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    update_dict = update.dict(exclude_unset=True)
    if not update_dict:
        raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")

    result = reportes_collection.update_one({"_id": reporte_id_obj}, {"$set": update_dict})
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="No se realizaron cambios")

    if "estado" in update_dict:
        user = usuarios_collection.find_one({"email": reporte["usuario"]})
        if user and "push_token" in user:
            message = messaging.Message(
                notification=messaging.Notification(
                    title="Reporte Actualizado",
                    body=f"El estado de tu reporte ha cambiado a: {update_dict['estado']}",
                ),
                token=user["push_token"],
            )
            try:
                messaging.send(message)
            except Exception as e:
                print(f"Error al enviar notificación: {str(e)}")

    return {"message": "Reporte actualizado"}

@app.get("/mis-reportes")
def listar_mis_reportes(current_user: dict = Depends(get_current_user)):
    reportes = list(reportes_collection.find({"usuario": current_user["email"]}, {"_id": 0}))
    return reportes

@app.get("/perfil")
def obtener_perfil(current_user: dict = Depends(get_current_user)):
    user = usuarios_collection.find_one({"email": current_user["email"]}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    reportes = list(reportes_collection.find({"usuario": current_user["email"]}))
    for reporte in reportes:
        reporte["_id"] = str(reporte["_id"])
        reporte["categoria_id"] = str(reporte["categoria_id"])
        del reporte["usuario"]
    return {"usuario": user, "reportes": reportes}

@app.post("/save-push-token")
def save_push_token(data: PushToken, current_user: dict = Depends(get_current_user)):
    usuarios_collection.update_one(
        {"email": current_user["email"]},
        {"$set": {"push_token": data.token}}
    )
    return {"message": "Token guardado"}

@app.post("/send-notification")
def send_notification(notification: Notification):
    user = usuarios_collection.find_one({"email": notification.user_email})
    if not user or "push_token" not in user:
        raise HTTPException(status_code=404, detail="Usuario o token no encontrado")
    
    message = messaging.Message(
        notification=messaging.Notification(
            title=notification.title,
            body=notification.body,
        ),
        token=user["push_token"],
    )
    
    try:
        response = messaging.send(message)
        return {"message": "Notificación enviada", "response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/estadisticas")
def obtener_estadisticas(current_admin: dict = Depends(get_current_admin)):
    estados = reportes_collection.aggregate([
        {"$group": {"_id": "$estado", "count": {"$sum": 1}}}
    ])
    estados_dict = {item["_id"]: item["count"] for item in estados}

    categorias = reportes_collection.aggregate([
        {"$group": {"_id": "$categoria_id", "count": {"$sum": 1}}}
    ])
    categorias_dict = {item["_id"]: item["count"] for item in categorias if item["_id"] is not None}

    total_reportes = reportes_collection.count_documents({})

    return {
        "total_reportes": total_reportes,
        "reportes_por_estado": estados_dict,
        "reportes_por_categoria": categorias_dict,
    }