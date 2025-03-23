import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler
import pyodbc
from datetime import timedelta
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
import hashlib
from sqlalchemy import text

# Configuración de la aplicación Flask
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.permanent_session_lifetime = timedelta(minutes=30)
# Actualiza el nombre de la base de datos a SistemaVideoDB
app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc://@localhost/SistemaVideoDB?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes"
db = SQLAlchemy(app)

# Configuración de logging
log_filename = 'sistema_video.log'
log_handler = RotatingFileHandler(log_filename, maxBytes=1024 * 1024, backupCount=5)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.DEBUG)

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Especifica la función de vista para el inicio de sesión


# Definición de los modelos de la base de datos
class Pelicula(db.Model):
    __tablename__ = 'Peliculas'
    id_pelicula = db.Column(db.Integer, primary_key=True, autoincrement=True, name='id_pelicula')
    nombre = db.Column(db.String(255), nullable=False, name='nombre')
    actores = db.Column(db.String(255), nullable=False, name='actores')

    def __repr__(self):
        return f'<Pelicula(nombre={self.nombre}, actores={self.actores})>'


class Cliente(UserMixin, db.Model):  # Hereda de UserMixin para Flask-Login
    __tablename__ = 'Clientes'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, name='id_cliente')  # Cambiado a 'id' para Flask-Login
    nombre = db.Column(db.String(255), nullable=False, name='nombre')
    email = db.Column(db.String(255), nullable=False, unique=True, name='email')
    password = db.Column(db.String(255), nullable=False, name='password')
    role = db.Column(db.String(10), nullable=False, default='cliente')  # Agregado rol

    def __repr__(self):
        return f'<Cliente(nombre={self.nombre}, email={self.email})>'


class Venta(db.Model):
    __tablename__ = 'Ventas'
    id_venta = db.Column(db.Integer, primary_key=True, autoincrement=True, name='id_venta')
    cliente_id = db.Column(db.Integer, db.ForeignKey('Clientes.id_cliente'), nullable=False, name='cliente_id')  # Cambiado a 'Clientes.id_cliente'
    pelicula_id = db.Column(db.Integer, db.ForeignKey('Peliculas.id_pelicula'), nullable=False, name='pelicula_id')
    fecha_venta = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), name='fecha_venta')
    cliente = db.relationship('Cliente', backref='ventas')
    pelicula = db.relationship('Pelicula', backref='ventas')

    def __repr__(self):
        return f'<Venta(id_venta={self.id_venta}, cliente_id={self.cliente_id}, pelicula_id={self.pelicula_id}, fecha_venta={self.fecha_venta})>'


# Crear las tablas en la base de datos
with app.app_context():
    try:
        # Elimina esta línea para evitar borrar las tablas existentes
        # db.drop_all()  
        db.create_all()
        print("Tablas creadas exitosamente!")
    except Exception as e:
        print(f"Error al crear las tablas: {e}")
        app.logger.error(f"Error al crear las tablas: {e}")


# Configuración de Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Cliente, int(user_id))  # Usa Session.get() en lugar de Query.get()


# Rutas y lógica de la aplicación
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        app.logger.debug(f"Intento de inicio de sesión con email: {email}")
        try:
            cliente = Cliente.query.filter_by(email=email).first()
            if cliente and check_password_hash(cliente.password, password):
                login_user(cliente)  # Inicia sesión con Flask-Login
                session['cliente_id'] = cliente.id
                session['cliente_nombre'] = cliente.nombre
                session['role'] = cliente.role  # Almacena el rol del usuario
                app.logger.info(f"Inicio de sesión exitoso para el cliente: {email}")
                if cliente.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('menu_principal'))
            else:
                flash('Correo electrónico o contraseña incorrectos', 'error')
                app.logger.warning(f"Inicio de sesión fallido para el cliente: {email}")
        except Exception as e:
            flash(f'Error al iniciar sesión: {e}', 'error')
            app.logger.error(f"Error al iniciar sesión para el cliente {email}: {e}")
    return render_template('login.html')


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    session.pop('cliente_id', None)
    session.pop('cliente_nombre', None)
    session.pop('role', None)
    app.logger.info("Sesión cerrada")
    return redirect(url_for('index'))


def is_admin():
    if not current_user.is_authenticated or current_user.role != 'admin':
        abort(403)  # Forbidden


@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        # Usa directamente 'pbkdf2:sha256' como método de hash
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        app.logger.debug(f"Intento de registro con email: {email}, nombre: {nombre}, método de hash: pbkdf2:sha256")
        try:
            existing_user = Cliente.query.filter_by(email=email).first()
            if existing_user:
                flash('El correo electrónico ya está registrado', 'error')
                app.logger.warning(f"El correo electrónico {email} ya está registrado")
                return render_template('register.html')
            nuevo_cliente = Cliente(nombre=nombre, email=email, password=hashed_password, role='cliente')  # Establece el rol por defecto
            db.session.add(nuevo_cliente)
            db.session.commit()
            app.logger.info(f"Nuevo cliente registrado: {email}, nombre: {nombre}")
            flash('Registro exitoso. Por favor, inicie sesión.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar el cliente: {e}', 'error')
            app.logger.error(f"Error al registrar el cliente {email}: {e}")
    return render_template('register.html')


@app.route('/menu_principal/')
@login_required
def menu_principal():
    try:
        peliculas = Pelicula.query.all()
        return render_template('menu_principal.html', peliculas=peliculas, cliente_nombre=current_user.nombre)
    except Exception as e:
        flash(f'Error al cargar el menú principal: {e}', 'error')
        app.logger.error(f"Error al cargar el menú principal para el cliente {current_user.nombre}: {e}")
        return render_template('menu_principal.html', peliculas=[], cliente_nombre=current_user.nombre)


@app.route('/buscar_peliculas/', methods=['GET'])
@login_required
def buscar_peliculas():
    query = request.args.get('query')
    app.logger.debug(f"Búsqueda de películas con query: {query} por el cliente: {current_user.nombre}")
    try:
        if query:
            peliculas = Pelicula.query.filter(
                db.or_(
                    Pelicula.nombre.ilike(f'%{query}%'),
                    Pelicula.actores.ilike(f'%{query}%')
                )
            ).all()
        else:
            peliculas = []
        return render_template('buscar_peliculas.html', peliculas=peliculas, query=query, cliente_nombre=current_user.nombre)
    except Exception as e:
        flash(f'Error al buscar películas: {e}', 'error')
        app.logger.error(f"Error al buscar películas con query {query} para el cliente {current_user.nombre}: {e}")
        return render_template('buscar_peliculas.html', peliculas=[], query=query, cliente_nombre=current_user.nombre)


@app.route('/carrito_de_compra/', methods=['GET', 'POST'])
@login_required
def carrito_de_compra():
    if request.method == 'POST':
        pelicula_id = request.form.get('pelicula_id')
        cantidad = int(request.form.get('cantidad', 1))
        app.logger.debug(f"Agregar película {pelicula_id} al carrito del cliente {current_user.nombre} con cantidad {cantidad}")
        try:
            pelicula = Pelicula.query.get(pelicula_id)
            if pelicula:
                if 'carrito' not in session:
                    session['carrito'] = {}
                if pelicula_id in session['carrito']:
                    session['carrito'][pelicula_id]['cantidad'] += cantidad
                else:
                    session['carrito'][pelicula_id] = {'nombre': pelicula.nombre, 'cantidad': cantidad, 'precio': 10.0}
                session.modified = True
                flash(f'{pelicula.nombre} ha sido agregada al carrito.', 'success')
                app.logger.info(f"Película {pelicula.nombre} agregada al carrito del cliente {current_user.nombre}")
            else:
                flash('Película no encontrada.', 'error')
                app.logger.warning(f"Película con ID {pelicula_id} no encontrada")
            return redirect(url_for('carrito_de_compra'))
        except Exception as e:
            flash(f'Error al agregar película al carrito: {e}', 'error')
            app.logger.error(f"Error al agregar película al carrito del cliente {current_user.nombre}: {e}")

    carrito = session.get('carrito', {})
    total_carrito = sum(item['cantidad'] * item['precio'] for item in carrito.values())
    return render_template('carrito_de_compra.html', carrito=carrito, total_carrito=total_carrito, cliente_nombre=current_user.nombre)


@app.route('/eliminar_del_carrito/<string:pelicula_id>', methods=['POST'])
@login_required
def eliminar_del_carrito(pelicula_id):
    app.logger.debug(f"Eliminar película {pelicula_id} del carrito del cliente {current_user.nombre}")
    try:
        if 'carrito' in session and pelicula_id in session['carrito']:
            del session['carrito'][pelicula_id]
            session.modified = True
            flash('Película eliminada del carrito.', 'success')
            app.logger.info(f"Película {pelicula_id} eliminada del carrito del cliente {current_user.nombre}")
        else:
            flash('La película no está en el carrito.', 'error')
            app.logger.warning(f"Intento de eliminar película {pelicula_id} no encontrada en el carrito del cliente {current_user.nombre}")
        return redirect(url_for('carrito_de_compra'))
    except Exception as e:
        flash(f'Error al eliminar película del carrito: {e}', 'error')
        app.logger.error(f"Error al eliminar película {pelicula_id} del carrito del cliente {current_user.nombre}: {e}")
        return redirect(url_for('carrito_de_compra'))


@app.route('/finalizar_compra/', methods=['POST'])
@login_required
def finalizar_compra():
    carrito = session.get('carrito', {})
    if not carrito:
        flash('El carrito está vacío.', 'error')
        return redirect(url_for('carrito_de_compra'))
    app.logger.debug(f"Finalizar compra para el cliente {current_user.nombre}")
    try:
        cliente_id = current_user.id
        for pelicula_id, detalles in carrito.items():  # Corregido 'en' por 'in'
            venta = Venta(cliente_id=cliente_id, pelicula_id=pelicula_id)
            db.session.add(venta)
        db.session.commit()
        session['carrito'] = {}
        session.modified = True
        flash('Compra realizada con éxito.', 'success')
        app.logger.info(f"Compra finalizada con éxito para el cliente {current_user.nombre}")
        return redirect(url_for('menu_principal'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error al finalizar la compra: {e}', 'error')
        app.logger.error(f"Error al finalizar la compra para el cliente {current_user.nombre}: {e}")
        return redirect(url_for('carrito_de_compra'))


@app.route('/mantenimiento_peliculas/', methods=['GET', 'POST'])
@login_required
def mantenimiento_peliculas():
    is_admin()
    if request.method == 'POST':
        if 'agregar' in request.form:
            nombre = request.form['nombre']
            actores = request.form['actores']
            app.logger.debug(f"Agregar película: {nombre}, Actores: {actores}")
            try:
                nueva_pelicula = Pelicula(nombre=nombre, actores=actores)
                db.session.add(nueva_pelicula)
                db.session.commit()
                flash('Película agregada con éxito.', 'success')
                app.logger.info(f"Película agregada: {nombre}, Actores: {actores}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al agregar película: {e}', 'error')
                app.logger.error(f"Error al agregar película: {e}")

        elif 'editar' in request.form:
            id_pelicula = request.form['id_pelicula']
            nombre = request.form['nombre']
            actores = request.form['actores']
            app.logger.debug(f"Editar película ID: {id_pelicula}, Nombre: {nombre}, Actores: {actores}")
            try:
                pelicula = Pelicula.query.get(id_pelicula)
                if pelicula:
                    pelicula.nombre = nombre
                    pelicula.actores = actores
                    db.session.commit()
                    flash('Película editada con éxito.', 'success')
                    app.logger.info(f"Película editada ID: {id_pelicula}, Nombre: {nombre}, Actores: {actores}")
                else:
                    flash('Película no encontrada.', 'error')
                    app.logger.warning(f"Película a editar no encontrada ID: {id_pelicula}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al editar película: {e}', 'error')
                app.logger.error(f"Error al editar película: {e}")

        elif 'eliminar' in request.form:
            id_pelicula = request.form['id_pelicula']
            app.logger.debug(f"Eliminar película ID: {id_pelicula}")
            try:
                pelicula = Pelicula.query.get(id_pelicula)
                if pelicula:
                    db.session.delete(pelicula)
                    db.session.commit()
                    flash('Película eliminada con éxito.', 'success')
                    app.logger.info(f"Película eliminada ID: {id_pelicula}")
                else:
                    flash('Película no encontrada.', 'error')
                    app.logger.warning(f"Película a eliminar no encontrada ID: {id_pelicula}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al eliminar película: {e}', 'error')
                app.logger.error(f"Error al eliminar película: {e}")
        return redirect(url_for('mantenimiento_peliculas'))

    peliculas = Pelicula.query.all()
    return render_template('mantenimiento_peliculas.html', peliculas=peliculas)


@app.route('/mantenimiento_usuarios/', methods=['GET', 'POST'])
@login_required
def mantenimiento_usuarios():
    is_admin()
    if request.method == 'POST':
        if 'editar' in request.form:
            id_cliente = request.form['id_cliente']
            nombre = request.form['nombre']
            email = request.form['email']
            app.logger.debug(f"Editar usuario ID: {id_cliente}, Nombre: {nombre}, Email: {email}")
            try:
                cliente = Cliente.query.get(id_cliente)
                if cliente:
                    cliente.nombre = nombre
                    cliente.email = email
                    db.session.commit()
                    flash('Usuario editado con éxito.', 'success')
                    app.logger.info(f"Usuario editado ID: {id_cliente}, Nombre: {nombre}, Email: {email}")
                else:
                    flash('Usuario no encontrado.', 'error')
                    app.logger.warning(f"Usuario a editar no encontrado ID: {id_cliente}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al editar usuario: {e}', 'error')
                app.logger.error(f"Error al editar usuario: {e}")
        elif 'eliminar' in request.form:
            id_cliente = request.form['id_cliente']
            app.logger.debug(f"Eliminar usuario ID: {id_cliente}")
            try:
                cliente = Cliente.query.get(id_cliente)
                if cliente:
                    db.session.delete(cliente)
                    db.session.commit()
                    flash('Usuario eliminado con éxito.', 'success')
                    app.logger.info(f"Usuario eliminado ID: {id_cliente}")
                else:
                    flash('Usuario no encontrado.', 'error')
                    app.logger.warning(f"Usuario a eliminar no encontrado ID: {id_cliente}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al eliminar usuario: {e}', 'error')
                app.logger.error(f"Error al eliminar usuario: {e}")
        return redirect(url_for('mantenimiento_usuarios'))

    clientes = Cliente.query.all()
    return render_template('mantenimiento_usuarios.html', clientes=clientes)


@app.route('/recuperar_password/', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        email = request.form['email']
        app.logger.debug(f"Intento de recuperación de contraseña para email: {email}")
        try:
            cliente = Cliente.query.filter_by(email=email).first()
            if cliente:
                flash('Se ha enviado un enlace de recuperación a su correo electrónico.', 'success')
                app.logger.info(f"Enlace de recuperación de contraseña enviado a: {email}")
                return redirect(url_for('login'))
            else:
                flash('Correo electrónico no encontrado.', 'error')
                app.logger.warning(f"Correo electrónico no encontrado: {email}")
        except Exception as e:
            flash(f'Error al procesar la solicitud de recuperación: {e}', 'error')
            app.logger.error(f"Error al procesar la solicitud de recuperación para {email}: {e}")
    return render_template('recuperar_password.html')


@app.route('/admin/user/<int:user_id>/set_role', methods=['POST'])
@login_required
def set_user_role(user_id):
    is_admin()
    user = db.session.get(Cliente, user_id)  # Usa Session.get() en lugar de Query.get()
    new_role = request.form['role']
    if new_role in ('cliente', 'admin'):
        user.role = new_role
        db.session.commit()
        flash('Rol de usuario actualizado.', 'success')
    else:
        flash('Rol inválido.', 'error')
    return redirect(url_for('mantenimiento_usuarios'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    is_admin()
    user = db.session.get(Cliente, user_id)  # Usa Session.get() en lugar de Query.get()
    db.session.delete(user)
    db.session.commit()
    flash('Usuario eliminado.', 'success')
    return redirect(url_for('mantenimiento_usuarios'))


@app.route('/admin/dashboard/', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    is_admin()
    if request.method == 'POST':
        accion = request.form['accion']  # Asegúrate de que 'accion' esté definida
        if accion == 'agregar_pelicula':
            nombre = request.form['nombre']
            actores = request.form['actores']
            app.logger.debug(f"Agregar película: {nombre}, Actores: {actores}")
            try:
                nueva_pelicula = Pelicula(nombre=nombre, actores=actores)
                db.session.add(nueva_pelicula)
                db.session.commit()
                flash('Película agregada con éxito.', 'success')
                app.logger.info(f"Película agregada: {nombre}, Actores: {actores}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al agregar película: {e}', 'error')
                app.logger.error(f"Error al agregar película: {e}")

        elif accion == 'editar_pelicula':
            id_pelicula = request.form['id_pelicula']
            nombre = request.form['nombre']
            actores = request.form['actores']
            app.logger.debug(f"Editar película ID: {id_pelicula}, Nombre: {nombre}, Actores: {actores}")
            try:
                pelicula = db.session.get(Pelicula, id_pelicula)  # Usa Session.get() en lugar de Query.get()
                if pelicula:
                    pelicula.nombre = nombre
                    pelicula.actores = actores
                    db.session.commit()
                    flash('Película editada con éxito.', 'success')
                    app.logger.info(f"Película editada ID: {id_pelicula}, Nombre: {nombre}, Actores: {actores}")
                else:
                    flash('Película no encontrada.', 'error')
                    app.logger.warning(f"Película a editar no encontrada ID: {id_pelicula}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al editar película: {e}', 'error')
                app.logger.error(f"Error al editar película: {e}")

        elif accion == 'eliminar_pelicula':
            id_pelicula = request.form['id_pelicula']
            app.logger.debug(f"Eliminar película ID: {id_pelicula}")
            try:
                pelicula = db.session.get(Pelicula, id_pelicula)  # Usa Session.get() en lugar de Query.get()
                if pelicula:
                    db.session.delete(pelicula)
                    db.session.commit()
                    flash('Película eliminada con éxito.', 'success')
                    app.logger.info(f"Película eliminada ID: {id_pelicula}")
                else:
                    flash('Película no encontrada.', 'error')
                    app.logger.warning(f"Película a eliminar no encontrada ID: {id_pelicula}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al eliminar película: {e}', 'error')
                app.logger.error(f"Error al eliminar película: {e}")

        elif accion == 'editar_usuario':
            id_cliente = request.form['id_cliente']
            nombre = request.form['nombre']
            email = request.form['email']
            app.logger.debug(f"Editar usuario ID: {id_cliente}, Nombre: {nombre}, Email: {email}")
            try:
                cliente = db.session.get(Cliente, id_cliente)  # Usa Session.get() en lugar de Query.get()
                if cliente:
                    cliente.nombre = nombre
                    cliente.email = email
                    db.session.commit()
                    flash('Usuario editado con éxito.', 'success')
                    app.logger.info(f"Usuario editado ID: {id_cliente}, Nombre: {nombre}, Email: {email}")
                else:
                    flash('Usuario no encontrado.', 'error')
                    app.logger.warning(f"Usuario a editar no encontrado ID: {id_cliente}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al editar usuario: {e}', 'error')
                app.logger.error(f"Error al editar usuario: {e}")

        elif accion == 'eliminar_usuario':
            id_cliente = request.form['id_cliente']
            app.logger.debug(f"Eliminar usuario ID: {id_cliente}")
            try:
                cliente = db.session.get(Cliente, id_cliente)  # Usa Session.get() en lugar de Query.get()
                if cliente:
                    db.session.delete(cliente)
                    db.session.commit()
                    flash('Usuario eliminado con éxito.', 'success')
                    app.logger.info(f"Usuario eliminado ID: {id_cliente}")
                else:
                    flash('Usuario no encontrado.', 'error')
                    app.logger.warning(f"Usuario a eliminar no encontrado ID: {id_cliente}")
            except Exception as e:
                db.session.rollback()
                flash(f'Error al eliminar usuario: {e}', 'error')
                app.logger.error(f"Error al eliminar usuario: {e}")

    peliculas = Pelicula.query.all()
    clientes = Cliente.query.all()

    # Datos para los gráficos
    ventas = db.session.query(
        text("CONVERT(VARCHAR, fecha_venta, 23) AS fecha"),
        db.func.count(Venta.id_venta).label('cantidad')
    ).group_by(text("CONVERT(VARCHAR, fecha_venta, 23)")).order_by(text("CONVERT(VARCHAR, fecha_venta, 23)")).all()

    # Verificar los resultados de la consulta
    for venta in ventas:
        app.logger.debug(f"Venta: {venta}")

    labels = [venta.fecha for venta in ventas]
    data = [venta.cantidad for venta in ventas]

    return render_template('admin_dashboard.html', peliculas=peliculas, clientes=clientes, labels=labels, data=data)

if __name__ == '__main__':
    app.run(debug=True)
