import socketio
import os
import eventlet
import mysql.connector
from mysql.connector import Error
import bcrypt
import re

# Crear una instancia de Socket.IO
sio = socketio.Server(cors_allowed_origins="*")

# Crear una aplicación de WSGI
app = socketio.WSGIApp(sio)

# Diccionario para almacenar SID y nombre de usuario
usuarios_conectados = {}
usuarios_playing = []

#Conexion a la base de datos
def ConexionDB():
    try:
        connection = mysql.connector.connect(
            host="34.132.193.227",
            database="chat-psa2",
            user="admin",
            password="admin123"
        )
        return connection
    except Error as ex:
        print(f"Error al conectarse a DB: {ex}")
        return None

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def es_password_seguro(password):
    if len(password) < 8:
        sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe tener al menos 8 caracteres."}, to=sid)
        return False
    if not re.search(r"[a-z]", password):
        sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos una letra minúscula."}, to=sid)
        return False
    if not re.search(r"[A-Z]", password):
        sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos una letra mayúscula."}, to=sid)
        return False
    if not re.search(r"[0-9]", password):
        sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos un número."}, to=sid)
        return False
    if not re.search(r"[\W_]", password):  # Caracter especial
        sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos un carácter especial."}, to=sid)
        return False
    return True
# Manejar la conexión de un cliente
@sio.event
def connect(sid, environ):
    print(f"Cliente conectado: {sid}")

# Manejar la desconexión de un cliente
@sio.event
def disconnect(sid):
    print("Usuario Desconectado")
    # Buscar el usuario desconectado por su SID
    usuario_desconectado = None
    for usuario, sid_actual in usuarios_conectados.items():
        if sid_actual == sid:
            usuario_desconectado = usuario
            break

    if usuario_desconectado:
        # Remover el usuario desconectado del diccionario
        del usuarios_conectados[usuario_desconectado]
        #Enviar un mensaje a todos los clientes conectados con el codigo del cliente desconectado
        for usuario, sid_actual in usuarios_conectados.items():
            sio.emit(
                'usuario_desconectado',  # Evento que recibirán los clientes
                {
                    'codigo_usuario': usuario_desconectado,
                    'mensaje': f'El usuario {usuario_desconectado} se ha desconectado.'
                },
                to=sid_actual  # Enviar mensaje al SID específico del usuario
            )
    else:
        print(f"DESCONEXION detectada para SID no registrado: {sid}")

# Manejar la reconexión del cliente
@sio.event
def reconnect(sid, data):
    # Se espera que el cliente envíe su identificador (e.g., nickname)
    nickname = data.get("nickname")
    if nickname:
        usuarios_conectados[nickname] = sid
        print(f"Usuario reconectado: {nickname}")
    else:
        print("Reconexión detectada, pero falta el identificador del usuario.")



# Manejar la recepción de mensajes
@sio.event
def mensaje(sid, data):
    print(f'SERVER ||Mensaje recibido: {data}')
    mensaje = data['Message']
    messageTo = data['to']
    codigo = obtener_codigo_por_nombre(usuarios_conectados, messageTo)
    print(f'SERVER || Reenviado a: {codigo}')
    sio.emit("mensajeCliente", mensaje, to=codigo)

@sio.event
def insert_usuario(sid, data):
    connDB = ConexionDB()
    if connDB is None:
        print("Error: No se pudo conectar a la base de datos.")
        sio.emit("registroRespuesta", {"success": False, "message": "Error en el servidor"}, to=sid)

    try:
        cursor = connDB.cursor()
        sql = """
            INSERT INTO Usuarios (usuario, nombre, password)
            VALUES (%s, %s, %s);
        """

        if len(data["password"]) < 8:
            sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe tener al menos 8 caracteres."}, to=sid)
            return False
        if not re.search(r"[a-z]", data["password"]):
            sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos una letra minúscula."}, to=sid)
            return False
        if not re.search(r"[A-Z]", data["password"]):
            sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos una letra mayúscula."}, to=sid)
            return False
        if not re.search(r"[0-9]", data["password"]):
            sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos un número."}, to=sid)
            return False
        if not re.search(r"[\W_]", data["password"]):  # Caracter especial
            sio.emit("registroRespuesta", {"success": False, "message": "La contraseña debe contener al menos un carácter especial."}, to=sid)
            return False
        # Hash de la contraseña
        hashed_password = hash_password(data["password"])

        cursor.execute(sql, (data["usuario"], data["nombre"],hashed_password))
        connDB.commit()
        sio.emit("registroRespuesta", {"success": True, "message": "Usuario registrado con éxito"}, to=sid)
    except Exception as e:
        if "Duplicate" in str(e):
            sio.emit("registroRespuesta", {"success": False, "message": "El usuario ya existe"}, to=sid)
        else:
            sio.emit("registroRespuesta", {"success": False, "message": "Error en el servidor"}, to=sid)
        print(f"Error al insertar el usuario: {e}")
        

#Obtener usuarios
@sio.event
def get_usuarios(sid):
    connDB = ConexionDB()
    if connDB is None:
        print("Error: No se pudo conectar a la base de datos.")
        sio.emit("getUsuarios", {"success": False, "message": "Error en el servidor"}, to=sid)

    try:
        cursor = connDB.cursor()
        sql = """
            SELECT id, name, nickname, status, s.victories  FROM users u inner join statistics s on u.id  = s.userId ;
        """

        cursor.execute(sql)
        usuarios = cursor.fetchall()

        usuarios_data = [
            {"id": user[0], "name": user[1], "nickname": user[2], "victories":user[4], "status": user[3]}
            for user in usuarios
        ]

        connDB.commit()
        sio.emit("getUsuarios", {"success": True, "data": usuarios_data}, to=sid)
    except Exception as e:
        print("Error al obtener los usuarios")
        sio.emit("getUsuarios", {"success": False, "message": "Error en el servidor"}, to=sid)

#Obtener SID del diccionario de usuarios conectados
def obtener_codigo_por_nombre(diccionario, nombre):
    return diccionario.get(nombre, None) 

# Manejo del login
@sio.event
def login(sid, data):
    connDB = ConexionDB()
    try:
        usuario = data["usuario"]
        password = data["password"]
        print(f"usuario: {usuario}, password: {password}")
        cursor = connDB.cursor()
        sql = "SELECT id, usuario, nombre, password FROM Usuarios WHERE usuario = %s;"
        
        cursor.execute(sql, (usuario, ))
        resultado = cursor.fetchone()
        print(f"resultado: {resultado}")
        
        if resultado is None:
            sio.emit("loginRespuesta", {"success": False, "message": "Usuario no encontrado"}, to=sid)
            return
        
        password_hash = resultado[3].encode('utf-8')  
        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            print("Contraseña correcta")
            usuarios_conectados[usuario] = sid
            sio.emit("loginRespuesta", {"success": True, "message": "Login exitoso"}, to=sid)
        else:
            print("Contraseña incorrecta")
            sio.emit("loginRespuesta", {"success": False, "message": "Credenciales incorrectas"}, to=sid)
    except KeyError as e:
        missing_key = str(e)
        sio.emit("loginRespuesta", {"success": False, "message": f"Falta el campo: {missing_key}"}, to=sid)
    except Exception as e:
        print("Error en login:", e)
        sio.emit("loginRespuesta", {"success": False, "message": "Error en el servidor"}, to=sid)

@sio.event
def getUserConectados(sid):
    print(f"user conectados: {usuarios_conectados}")
    for usuario, sid_actual in usuarios_conectados.items():
        sio.emit("getUserOnlineResp", {"success": True, "data": list(usuarios_conectados.keys())}, to=sid_actual)

    # sio.emit("getUserOnlineResp", {"success": True, "data": list(usuarios_conectados.keys())}, to=sid)


@sio.event
def save_chat(sid, data):
    connDB = ConexionDB()
    if connDB is None:
        print("Error: No se pudo conectar a la base de datos.")
        sio.emit("registroChatRespuesta", {"success": False, "message": "Error en el servidor"}, to=sid)

    try:
        cursor = connDB.cursor()
        sql = "SELECT code FROM Chats c  WHERE code like '%'%s'%' and code like '%'%s'%';"
        cursor.execute(sql, (data["user1"], data["user2"]))
        resultado = cursor.fetchone()

        if resultado:
            sql = """
                UPDATE Chats SET chat=%s WHERE code like '%'%s'%' and code like '%'%s'%'
            """   
            cursor.execute(sql, (data["chat"], data["user1"], data["user2"]))
        else:
            sql = """
                INSERT INTO Chats (code, chat)
                VALUES (%s, %s);
            """   
            cursor.execute(sql, (data["code"], data["chat"]))
        connDB.commit()
        sio.emit("registroChatRespuesta", {"success": True, "message": "Chat registrado con éxito"}, to=sid)
    except Exception as e:
        print(f"Error al insertar el usuario: {e}")
        sio.emit("registroChatRespuesta", {"success": False, "message": "Error en el servidor"}, to=sid)


# Ejecutar el servidor
if __name__ == '__main__':
    # eventlet.wsgi.server(eventlet.listen(('localhost', 5000)), app)   
    port = int(os.environ.get("PORT", 5000))  # Usar el puerto de la variable de entorno o 5000 por defecto
    eventlet.wsgi.server(eventlet.listen(("", port)), app)