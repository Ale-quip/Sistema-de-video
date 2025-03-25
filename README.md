# Sistema de Gestión de Biblioteca

![Estado del Proyecto](https://img.shields.io/badge/Estado-En%20Desarrollo-yellow)
![Licencia](https://img.shields.io/badge/Licencia-MIT-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey)
![SQL Server](https://img.shields.io/badge/SQL%20Server-2019-red)

## 📋 Contenido

- [Descripción](#descripción)
- [Características](#características)
- [Requisitos del Sistema](#requisitos-del-sistema)
- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso](#uso)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [API y Rutas](#api-y-rutas)

## 📝 Descripción

Sistema de Gestión de Biblioteca es una aplicación web desarrollada con Python y Flask que permite administrar una biblioteca moderna. El sistema facilita la gestión de libros, usuarios y ventas, ofreciendo una interfaz intuitiva tanto para administradores como para usuarios.

## ✨ Características

### Para Usuarios
- **Autenticación de usuarios**
  - Registro de nuevos usuarios
  - Inicio de sesión
  - Recuperación de contraseña
- **Catálogo de libros**
  - Visualización de todos los libros disponibles
  - Búsqueda por título, autor o género
  - Filtrado por categorías
- **Carrito de compras**
  - Añadir libros al carrito
  - Modificar cantidades
  - Proceso de checkout
- **Historial de compras**
  - Visualización de compras anteriores
  - Detalles de transacciones

### Para Administradores
- **Gestión de libros**
  - Añadir nuevos libros
  - Editar información existente
  - Eliminar libros
  - Gestión de inventario
- **Gestión de usuarios**
  - Ver todos los usuarios
  - Modificar roles
  - Gestionar permisos
- **Gestión de ventas**
  - Ver historial de ventas
  - Generar reportes
  - Estadísticas de ventas

## 💻 Requisitos del Sistema

- Python 3.6 o superior
- SQL Server 2019 o superior
- Drivers ODBC para SQL Server
- pip (gestor de paquetes de Python)
- Navegador web moderno

## 🚀 Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/tu-usuario/sistema-biblioteca.git
cd sistema-biblioteca
```

2. **Crear y activar entorno virtual**
```bash
python -m venv venv
.\venv\Scripts\activate
```

3. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

## ⚙️ Configuración

1. **Base de datos**
- Crear una base de datos llamada 'BibliotecaDB' en SQL Server
- Ejecutar el script de inicialización ubicado en `database/init.sql`

2. **Variables de entorno**
Crear un archivo `.env` en la raíz del proyecto:
```
DB_SERVER=tu_servidor
DB_DATABASE=BibliotecaDB
DB_USERNAME=tu_usuario
DB_PASSWORD=tu_contraseña
SECRET_KEY=tu_clave_secreta
```

## 📚 Uso

1. **Iniciar el servidor**
```bash
python app.py
```

2. **Acceder a la aplicación**
- Abrir navegador en `http://localhost:5000`
- Credenciales por defecto del administrador:
  - Usuario: admin
  - Contraseña: admin123

## 📁 Estructura del Proyecto

```
biblioteca/
├── app.py              # Aplicación principal
├── config.py           # Configuración
├── requirements.txt    # Dependencias
├── static/            # Archivos estáticos
├── templates/         # Plantillas HTML
├── database/         # Scripts SQL
└── routes/           # Rutas de la aplicación
```

## 🔄 API y Rutas

### Rutas Públicas
- `/` - Página principal
- `/login` - Inicio de sesión
- `/register` - Registro de usuarios
- `/catalog` - Catálogo de libros
- `/book/<id>` - Detalles de libro

### Rutas de Usuario
- `/cart` - Carrito de compras
- `/checkout` - Proceso de compra
- `/profile` - Perfil de usuario
- `/orders` - Historial de compras

### Rutas de Administrador
- `/admin` - Panel de administración
- `/admin/books` - Gestión de libros
- `/admin/users` - Gestión de usuarios
- `/admin/sales` - Reportes de ventas
