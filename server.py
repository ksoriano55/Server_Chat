import socketio
import os
import eventlet
import mysql.connector
from mysql.connector import Error

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
            host="34.42.104.166",
            database="localhost",
            user="root",
            password="123456"
        )
        return connection
    except Error as ex:
        print(f"Error al conectarse a DB: {ex}")
        return None


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
    print(f'Mensaje recibido: {data}')
    mensaje = data['newMessage']
    contrincante = data['userContrincante']
    codigo = obtener_codigo_por_nombre(usuarios_conectados, contrincante)
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
            INSERT INTO users (name, password, nickname, status)
            VALUES (%s, %s, %s, %s);
        """
      
        cursor.execute(sql, (data["name"], data["password"], data["nickname"], data["status"]))
        connDB.commit()
        sio.emit("registroRespuesta", {"success": True, "message": "Usuario registrado con éxito"}, to=sid)
    except Exception as e:
        print(f"Error al insertar el usuario: {e}")
        sio.emit("registroRespuesta", {"success": False, "message": "Error en el servidor"}, to=sid)

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
        nickname = data["nickname"]
        password = data["password"]
        cursor = connDB.cursor()
        sql = "SELECT nickname FROM users u WHERE nickname = %s and password = %s;"
        cursor.execute(sql, (nickname, password))
        resultado = cursor.fetchone()

        if resultado:
            # Marcar cliente como conectado
            usuarios_conectados[nickname] = sid
            sio.emit("loginRespuesta", {"success": True, "message": "Login exitoso"}, to=sid)
        else:
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
    
# Ejecutar el servidor
if __name__ == '__main__':
    # eventlet.wsgi.server(eventlet.listen(('localhost', 5000)), app)   
    port = int(os.environ.get("PORT", 5000))  # Usar el puerto de la variable de entorno o 5000 por defecto
    eventlet.wsgi.server(eventlet.listen(("", port)), app)