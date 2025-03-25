import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv


dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Configuración de SQL Server
conn_str = (
    "Driver={SQL Server};"
    "Server=localhost;"
    "Database=BibliotecaDB;"
    "Trusted_Connection=yes;"  
)

# Inicializar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Clase de usuario para Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

# Función para obtener usuario por ID
@login_manager.user_loader
def load_user(user_id):
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, is_admin FROM usuarios WHERE id = ?", user_id)
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

# Función para crear las tablas en la base de datos
def setup_database():
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    
    # Crear tabla de usuarios
    cursor.execute('''
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='usuarios' AND xtype='U')
    CREATE TABLE usuarios (
        id INT PRIMARY KEY IDENTITY(1,1),
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        is_admin BIT DEFAULT 0
    )
    ''')
    
    # Crear tabla de libros
    cursor.execute('''
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='libros' AND xtype='U')
    CREATE TABLE libros (
        id INT PRIMARY KEY IDENTITY(1,1),
        titulo VARCHAR(100) NOT NULL,
        descripcion TEXT,
        autor VARCHAR(255),
        genero VARCHAR(50),
        anio_publicacion INT,
        precio DECIMAL(10, 2) NOT NULL,
        imagen_url VARCHAR(500)
    )
    ''')
    
    # Crear tabla de ventas
    cursor.execute('''
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ventas' AND xtype='U')
    CREATE TABLE ventas (
        id INT PRIMARY KEY IDENTITY(1,1),
        usuario_id INT NOT NULL,
        fecha DATETIME NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
    )
    ''')
    
    # Crear tabla de detalles de venta
    cursor.execute('''
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='detalle_ventas' AND xtype='U')
    CREATE TABLE detalle_ventas (
        id INT PRIMARY KEY IDENTITY(1,1),
        venta_id INT NOT NULL,
        libro_id INT NOT NULL,
        precio DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (venta_id) REFERENCES ventas(id),
        FOREIGN KEY (libro_id) REFERENCES libros(id)
    )
    ''')
    
    # Crear un usuario administrador por defecto
    cursor.execute("IF NOT EXISTS (SELECT * FROM usuarios WHERE username = 'admin') INSERT INTO usuarios (username, email, password, is_admin) VALUES (?, ?, ?, ?)", 
                  'admin', 'admin@example.com', generate_password_hash('admin123'), 1)
    
    conn.commit()
    conn.close()

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset-salt')

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return False
    return email

# Rutas de la aplicación
@app.route('/')
def index():
    return redirect(url_for('login'))

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, password, is_admin FROM usuarios WHERE username = ?", username)
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[3], password):
            user = User(user_data[0], user_data[1], user_data[2], user_data[4])
            login_user(user)
            return redirect(url_for('catalogo'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')
    
    return render_template('login.html')

# Ruta de registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return render_template('registro.html')
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)", 
                          username, email, hashed_password)
            conn.commit()
            conn.close()
            
            flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        except pyodbc.IntegrityError:
            flash('El nombre de usuario o email ya está en uso', 'danger')
        
    return render_template('registro.html')

# Ruta para recuperar contraseña
@app.route('/recuperar-password', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", email)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            token = generate_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Modificar la creación del mensaje
            subject = 'Recuperación de Contraseña - Sistema de Libros'
            
            # Crear el mensaje con el remitente configurado en la aplicación
            msg = Message(
                subject=subject,
                recipients=[email]
            )
            
            msg.body = f'''Para restablecer tu contraseña, visita el siguiente enlace:
{reset_url}

Si no solicitaste un restablecimiento de contraseña, ignora este correo.

Este enlace expirará en 1 hora.
'''
            msg.html = f'''
<p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
<p><a href="{reset_url}">Restablecer Contraseña</a></p>
<p>Si no solicitaste un restablecimiento de contraseña, ignora este correo.</p>
<p>Este enlace expirará en 1 hora.</p>
'''
            
            try:
                mail.send(msg)
                flash('Se ha enviado un enlace de recuperación a tu correo electrónico', 'success')
            except Exception as e:
                print(f"Error al enviar correo: {str(e)}")
                flash('Error al enviar el correo de recuperación. Por favor, intenta más tarde.', 'danger')
            
            return redirect(url_for('login'))
        else:
            flash('No se encontró ninguna cuenta con ese correo electrónico', 'danger')
    
    return render_template('recuperar_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if not email:
        flash('El enlace de recuperación es inválido o ha expirado', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(password)
        
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios SET password = ? WHERE email = ?", hashed_password, email)
        conn.commit()
        conn.close()
        
        flash('Tu contraseña ha sido actualizada', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

# Ruta de catálogo de libros
@app.route('/catalogo')
@login_required
def catalogo():
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM libros ORDER BY titulo")
    libros = cursor.fetchall()
    conn.close()
    return render_template('catalogo.html', libros=libros)

# Ruta para añadir al carrito
@app.route('/agregar-carrito/<int:libro_id>')
@login_required
def agregar_carrito(libro_id):
    if 'carrito' not in session:
        session['carrito'] = []
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT id, titulo, precio FROM libros WHERE id = ?", libro_id)
    libro = cursor.fetchone()
    conn.close()
    
    if libro:
        item = {
            'id': libro[0],
            'titulo': libro[1],
            'precio': float(libro[2])
        }
        session['carrito'].append(item)
        session.modified = True
        flash('Libro agregado al carrito', 'success')
    
    return redirect(url_for('catalogo'))

# Ruta para ver el carrito
@app.route('/carrito')
@login_required
def carrito():
    if 'carrito' not in session:
        session['carrito'] = []
    
    total = sum(item['precio'] for item in session['carrito'])
    
    return render_template('carrito.html', carrito=session['carrito'], total=total)

# Ruta para eliminar del carrito
@app.route('/eliminar-carrito/<int:index>')
@login_required
def eliminar_carrito(index):
    if 'carrito' in session and 0 <= index < len(session['carrito']):
        session['carrito'].pop(index)
        session.modified = True
        flash('Libro eliminado del carrito', 'success')
    
    return redirect(url_for('carrito'))

# Ruta para procesar la compra
@app.route('/comprar')
@login_required
def comprar():
    if 'carrito' not in session or not session['carrito']:
        flash('Tu carrito está vacío', 'info')
        return redirect(url_for('catalogo'))
    
    total = sum(item['precio'] for item in session['carrito'])
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    
    # Crear la venta
    cursor.execute("INSERT INTO ventas (usuario_id, fecha, total) VALUES (?, ?, ?)", 
                  current_user.id, datetime.now(), total)
    cursor.execute("SELECT @@IDENTITY")
    venta_id = cursor.fetchone()[0]
    
    # Crear los detalles de la venta
    for item in session['carrito']:
        cursor.execute("INSERT INTO detalle_ventas (venta_id, libro_id, precio) VALUES (?, ?, ?)", 
                      venta_id, item['id'], item['precio'])
    
    conn.commit()
    conn.close()
    
    # Limpiar el carrito
    session['carrito'] = []
    session.modified = True
    
    flash('¡Compra realizada con éxito!', 'success')
    return redirect(url_for('catalogo'))

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rutas de administración
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('No tienes permisos para acceder a esta página', 'danger')
        return redirect(url_for('catalogo'))
    
    return render_template('admin/index.html')

# Administración de libros
@app.route('/admin/libros')
@login_required
def admin_libros():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('catalogo'))
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM libros ORDER BY titulo")
    libros = cursor.fetchall()
    conn.close()
    
    return render_template('admin/libros.html', libros=libros)

@app.route('/admin/libros/agregar', methods=['GET', 'POST'])
@login_required
def admin_agregar_libro():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('catalogo'))
    
    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        autor = request.form['autor']
        genero = request.form['genero']
        anio_publicacion = request.form['anio_publicacion']
        precio = request.form['precio']
        imagen_url = request.form['imagen_url']
        
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO libros (titulo, descripcion, autor, genero, anio_publicacion, precio, imagen_url)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, titulo, descripcion, autor, genero, anio_publicacion, precio, imagen_url)
        conn.commit()
        conn.close()
        
        flash('Libro agregado exitosamente', 'success')
        return redirect(url_for('admin_libros'))
    
    return render_template('admin/agregar_libro.html')

@app.route('/admin/libros/editar/<int:libro_id>', methods=['GET', 'POST'])
@login_required
def admin_editar_libro(libro_id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('catalogo'))
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        autor = request.form['autor']
        genero = request.form['genero']
        anio_publicacion = request.form['anio_publicacion']
        precio = request.form['precio']
        imagen_url = request.form['imagen_url']
        
        cursor.execute("""
            UPDATE libros 
            SET titulo=?, descripcion=?, autor=?, genero=?, anio_publicacion=?, precio=?, imagen_url=?
            WHERE id=?
        """, titulo, descripcion, autor, genero, anio_publicacion, precio, imagen_url, libro_id)
        conn.commit()
        flash('Libro actualizado exitosamente', 'success')
        return redirect(url_for('admin_libros'))
    
    cursor.execute("SELECT * FROM libros WHERE id = ?", libro_id)
    libro = cursor.fetchone()
    conn.close()
    
    if libro is None:
        flash('Libro no encontrado', 'danger')
        return redirect(url_for('admin_libros'))
    
    return render_template('admin/editar_libro.html', libro=libro)

@app.route('/admin/libros/eliminar/<int:libro_id>')
@login_required
def admin_eliminar_libro(libro_id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('catalogo'))
    
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        # Primero eliminar los detalles de venta relacionados
        cursor.execute("DELETE FROM detalle_ventas WHERE libro_id = ?", libro_id)
        
        # Luego eliminar el libro
        cursor.execute("DELETE FROM libros WHERE id = ?", libro_id)
        
        conn.commit()
        conn.close()
        flash('Libro eliminado exitosamente', 'success')
    except Exception as e:
        flash('Error al eliminar el libro', 'danger')
    
    return redirect(url_for('admin_libros'))

# Administración de usuarios
@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if not current_user.is_admin:
        flash('Acceso denegado', 'danger')
        return redirect(url_for('index'))
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, is_admin FROM usuarios")
    usuarios = cursor.fetchall()
    conn.close()
    
    return render_template('admin_usuarios.html', usuarios=usuarios)

# Ruta para agregar usuario desde el admin
@app.route('/admin/usuarios/agregar', methods=['GET', 'POST'])
@login_required
def admin_agregar_usuario():
    if not current_user.is_admin:
        flash('Acceso denegado', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = True if request.form.get('is_admin') else False
        
        try:
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            
            # Verificar si el usuario ya existe
            cursor.execute("SELECT id FROM usuarios WHERE username = ? OR email = ?", 
                         username, email)
            if cursor.fetchone():
                flash('El nombre de usuario o email ya está en uso', 'danger')
                return redirect(url_for('admin_agregar_usuario'))
            
            # Crear el nuevo usuario
            hashed_password = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO usuarios (username, email, password, is_admin)
                VALUES (?, ?, ?, ?)
            """, username, email, hashed_password, is_admin)
            conn.commit()
            
            flash('Usuario creado exitosamente', 'success')
            return redirect(url_for('admin_usuarios'))
            
        except Exception as e:
            flash('Error al crear el usuario: ' + str(e), 'danger')
            return redirect(url_for('admin_agregar_usuario'))
        finally:
            conn.close()
    
    return render_template('admin_agregar_usuario.html')

# Ruta para cambiar rol de usuario
@app.route('/admin/usuarios/cambiar-rol/<int:usuario_id>')
@login_required
def admin_cambiar_rol(usuario_id):
    if not current_user.is_admin:
        flash('Acceso denegado', 'danger')
        return redirect(url_for('index'))
    
    # No permitir cambiar el rol del usuario actual
    if usuario_id == current_user.id:
        flash('No puedes cambiar tu propio rol', 'danger')
        return redirect(url_for('admin_usuarios'))
    
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        # Verificar si el usuario existe
        cursor.execute("SELECT username, is_admin FROM usuarios WHERE id = ?", usuario_id)
        result = cursor.fetchone()
        
        if not result:
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('admin_usuarios'))
            
        username, is_admin = result
        
        # Cambiar el estado
        nuevo_estado = not is_admin
        cursor.execute("UPDATE usuarios SET is_admin = ? WHERE id = ?", nuevo_estado, usuario_id)
        conn.commit()
        
        mensaje = f'Usuario "{username}" ahora es {"administrador" if nuevo_estado else "usuario normal"}'
        flash(mensaje, 'success')
        
    except Exception as e:
        flash(f'Error al cambiar el rol: {str(e)}', 'danger')
    finally:
        conn.close()
        
    return redirect(url_for('admin_usuarios'))

# Ruta para eliminar usuario
@app.route('/admin/usuarios/eliminar/<int:usuario_id>')
@login_required
def admin_eliminar_usuario(usuario_id):
    if not current_user.is_admin:
        return redirect(url_for('catalogo'))
    
    # No permitir eliminar al usuario actual
    if usuario_id == current_user.id:
        flash('No puedes eliminar tu propio usuario', 'danger')
        return redirect(url_for('admin_usuarios'))
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    
    # Verificar si el usuario tiene ventas
    cursor.execute("SELECT COUNT(*) FROM ventas WHERE usuario_id = ?", usuario_id)
    count = cursor.fetchone()[0]
    
    if count > 0:
        flash('No se puede eliminar este usuario porque tiene ventas asociadas', 'danger')
    else:
        cursor.execute("DELETE FROM usuarios WHERE id = ?", usuario_id)
        conn.commit()
        flash('Usuario eliminado con éxito', 'success')
    
    conn.close()
    return redirect(url_for('admin_usuarios'))

# Inicializar la base de datos y ejecutar la aplicación
if __name__ == '__main__':
    setup_database()
    app.run(debug=True)