from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

import re

# Crear la aplicación Flask
app = Flask(__name__)

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ontour.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'b29f4a0745209581de11f6ee26564b36'  # Importante para las sesiones

# Inicializar base de datos y migraciones
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Inicializar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirige a 'login' si no estás autenticado

# Modelos de la base de datos
class Apoderado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    rut = db.Column(db.String(10), unique=True, nullable=False)
    curso_id = db.Column(db.Integer, db.ForeignKey('curso.id'), nullable=False)
    pagos = db.relationship('Pago', backref='apoderado', lazy=True)

class Curso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apoderados = db.relationship("Apoderado", backref="curso", lazy=True)

class Alumno(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    rut_apoderado = db.Column(db.String(10), db.ForeignKey('apoderado.rut'), nullable=False)

class Pago(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    monto = db.Column(db.Float, nullable=False)
    fecha = db.Column(db.Date, default=datetime.utcnow)
    apoderado_id = db.Column(db.Integer, db.ForeignKey('apoderado.id'), nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50))  # Asegúrate de que esta línea esté presente

# Redirigir la página principal a la vista de base
@app.route('/')
def index():
    return render_template('base.html')

# Vista para login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Verificar el correo y la contraseña
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            # Redirigir basado en el rol del usuario
            if user.role == 'ejecutivo':
                return redirect(url_for('ejecutivo_home'))  # Redirige a la página de ejecutivo
            elif user.role == 'apoderado':
                return redirect(url_for('apoderado_home'))  # Redirige sin el id
        else:
            flash('Correo electrónico o contraseña incorrectos', 'error')

    return render_template('login.html')

# Vista de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Vista principal de ejecutivo
@app.route('/ejecutivo')
@login_required
def ejecutivo_home():
    cursos = Curso.query.all()
    apoderados = Apoderado.query.all()
    return render_template('ejecutivo_home.html', cursos=cursos, apoderados=apoderados)

@app.route('/ver_apoderados')
def ver_apoderados():
    try:
        # Obtener la lista de apoderados desde la base de datos
        apoderados = Apoderado.query.all()
        return render_template('ver_apoderados.html', apoderados=apoderados)
    except Exception as e:
        print(f"Error al obtener apoderados: {e}")
        return "Hubo un problema al cargar la lista de apoderados."


# Vista para mostrar los detalles de un curso
@app.route('/apoderado_home')
def apoderado_home():
    apoderado = obtener_apoderado_actual()  # Obtener apoderado actual desde la sesión
    cursos = obtener_cursos_asociados(apoderado.id)  # Obtener los cursos asociados
    return render_template('apoderado_home.html', cursos=cursos)

@app.route('/detalle_curso/<int:curso_id>')
def detalle_curso(curso_id):
    curso = obtener_detalles_curso(curso_id)  # Obtener detalles del curso
    return render_template('detalle_curso.html', curso=curso)

@app.route('/realizar_pago/<int:curso_id>', methods=['GET', 'POST'])
def realizar_pago(curso_id):
    curso = obtener_detalles_curso(curso_id)
    if request.method == 'POST':
        # Lógica para realizar el pago
        realizar_pago(curso_id, request.form['monto_pago'])
        return redirect(url_for('detalle_curso', curso_id=curso_id))
    return render_template('realizar_pago.html', curso=curso)

@app.route('/ver_pagos_realizados/<int:curso_id>')
def ver_pagos_realizados(curso_id):
    pagos = obtener_pagos_realizados(curso_id)
    return render_template('ver_pagos_realizados.html', pagos=pagos)

def obtener_apoderado_actual():
    if 'apoderado_id' in session:  # Si el apoderado está logueado (almacenado en sesión)
        apoderado_id = session['apoderado_id']
        apoderado = Apoderado.query.get(apoderado_id)  # Asumiendo que Apoderado es tu modelo
        return apoderado
    else:
        flash('No has iniciado sesión como apoderado', 'danger')
        return redirect(url_for('login'))  # Redirige al login si no hay sesión activa

@app.route('/crear_curso', methods=['GET', 'POST'])
@login_required
def crear_curso():
    if request.method == 'POST':
        nombre = request.form['nombre']

        # Verificar si el curso ya existe
        if Curso.query.filter_by(nombre=nombre).first():
            flash('El curso ya existe', 'danger')
            return redirect(url_for('crear_curso'))

        nuevo_curso = Curso(nombre=nombre)
        
        try:
            db.session.add(nuevo_curso)
            db.session.commit()
            flash('Curso creado con éxito', 'success')
            return redirect(url_for('ejecutivo_home'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el curso: {str(e)}', 'danger')

    return render_template('crear_curso.html')

@app.route('/crear_apoderado', methods=['GET', 'POST'])
@login_required
def crear_apoderado():
    if request.method == 'POST':
        nombre = request.form['nombre']
        rut = request.form['rut']
        curso_id = request.form['curso_id']

        # Verificar que el RUT no esté duplicado
        if Apoderado.query.filter_by(rut=rut).first():
            flash('El RUT ya está registrado', 'danger')
            return redirect(url_for('crear_apoderado'))

        nuevo_apoderado = Apoderado(nombre=nombre, rut=rut, curso_id=curso_id)
        
        try:
            db.session.add(nuevo_apoderado)
            db.session.commit()
            flash('Apoderado creado con éxito', 'success')
            return redirect(url_for('ejecutivo_home'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el apoderado: {str(e)}', 'danger')
    
    # Obtener los cursos para mostrar en el formulario
    cursos = Curso.query.all()
    return render_template('crear_apoderado.html', cursos=cursos)

@app.route('/crear_alumno', methods=['GET', 'POST'])
@login_required
def crear_alumno():
    if request.method == 'POST':
        nombre = request.form['nombre']
        rut_apoderado = request.form['rut_apoderado']

        # Verificar si el apoderado existe
        apoderado = Apoderado.query.filter_by(rut=rut_apoderado).first()
        if not apoderado:
            flash('El apoderado no existe', 'danger')
            return redirect(url_for('crear_alumno'))

        nuevo_alumno = Alumno(nombre=nombre, rut_apoderado=rut_apoderado)
        
        try:
            db.session.add(nuevo_alumno)
            db.session.commit()
            flash('Alumno creado con éxito', 'success')
            return redirect(url_for('ejecutivo_home'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el alumno: {str(e)}', 'danger')
    
    # Obtener apoderados para mostrar en el formulario
    apoderados = Apoderado.query.all()
    return render_template('crear_alumno.html', apoderados=apoderados)


# Vista para registro de usuario
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Validación de correo electrónico
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Correo electrónico no válido', 'danger')
            return redirect(url_for('registro'))

        # Verificar si el correo ya está registrado
        if User.query.filter_by(email=email).first():
            flash('El correo ya está registrado', 'danger')
            return redirect(url_for('registro'))

        # Validación del rol
        if role not in ['apoderado', 'ejecutivo']:
            flash('Rol inválido', 'danger')
            return redirect(url_for('registro'))

        # Hash de la contraseña
        hashed_password = generate_password_hash(password)

        # Crear el nuevo usuario
        nuevo_usuario = User(email=email, password=hashed_password, role=role)

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash('Usuario registrado con éxito', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error al registrar usuario: ' + str(e), 'danger')

    return render_template('registro.html')

# Función para cargar un usuario desde su ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    app.run(debug=True)
