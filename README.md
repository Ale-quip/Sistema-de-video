# Sistema de Video

![Estado del Proyecto](https://img.shields.io/badge/Estado-En%20Desarrollo-yellow)
![Licencia](https://img.shields.io/badge/Licencia-MIT-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey)
![SQL Server](https://img.shields.io/badge/SQL%20Server-2019-red)

## 📋 Contenido

- [Descripción](#descripción)
- [Características](#características)
- [Capturas de Pantalla](#capturas-de-pantalla)
- [Tecnologías Utilizadas](#tecnologías-utilizadas)
- [Requisitos Previos](#requisitos-previos)
- [Instalación](#instalación)
  - [Clonar el Repositorio](#clonar-el-repositorio)
  - [Configurar el Entorno Virtual](#configurar-el-entorno-virtual)
  - [Instalar Dependencias](#instalar-dependencias)
- [Configuración](#configuración)
  - [Base de Datos](#base-de-datos)
  - [Variables de Entorno (Opcional)](#variables-de-entorno-opcional)
- [Ejecución](#ejecución)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Guía de Uso](#guía-de-uso)
  - [Autenticación](#autenticación)
  - [Catálogo de Películas](#catálogo-de-películas)
  - [Carrito de Compras](#carrito-de-compras)
  - [Panel de Administración](#panel-de-administración)
- [Imágenes de Películas](#imágenes-de-películas)
- [Modelo de Datos](#modelo-de-datos)
- [API y Rutas](#api-y-rutas)
- [Seguridad](#seguridad)
- [Solución de Problemas](#solución-de-problemas)
- [Mejoras Futuras](#mejoras-futuras)
- [Contribuir](#contribuir)
- [Licencia](#licencia)
- [Contacto](#contacto)

## 📝 Descripción

Sistema de Video es una aplicación web completa desarrollada con Python, Flask y SQL Server que simula una plataforma de venta de películas en línea. El sistema permite a los usuarios registrarse, explorar un catálogo de películas, añadirlas a un carrito de compras y realizar compras. También incluye un robusto panel de administración para gestionar películas y usuarios.

Este proyecto fue desarrollado como una solución integral para tiendas de video que desean digitalizar su inventario y ofrecer servicios de venta en línea.

## ✨ Características

### Para Usuarios
- **Registro e inicio de sesión**: Sistema completo de autenticación de usuarios
- **Recuperación de contraseña**: Mecanismo para restablecer contraseñas olvidadas
- **Catálogo de películas**: Visualización de todas las películas disponibles
- **Búsqueda avanzada**: Filtrado por título o actores
- **Carrito de compras**: Añadir películas y gestionar el carrito
- **Proceso de compra**: Finalización de compras y registro de transacciones

### Para Administradores
- **Gestión de películas**: Añadir, editar y eliminar películas del catálogo
- **Gestión de usuarios**: Administrar usuarios, cambiar roles y eliminar cuentas
- **Panel de control**: Interfaz intuitiva para todas las operaciones administrativas

## 📸 Capturas de Pantalla

> Nota: A continuación se describen las principales pantallas del sistema. En un repositorio real, aquí se incluirían imágenes de la aplicación.

### Pantalla de Inicio de Sesión
Interfaz limpia y moderna con campos para nombre de usuario y contraseña, opciones para registrarse y recuperar contraseña.

### Catálogo de Películas
Cuadrícula de tarjetas de películas con imágenes, títulos, precios y botones para añadir al carrito. Barra de búsqueda en la parte superior.

### Carrito de Compras
Lista detallada de películas seleccionadas, con opciones para eliminar items y un botón para finalizar la compra.

### Panel de Administración
Interfaz dividida en secciones para gestionar películas y usuarios, con tablas de datos y opciones de edición.

## 🛠️ Tecnologías Utilizadas

- **Backend**: Python 3.6+, Flask 2.0+
- **Base de Datos**: Microsoft SQL Server 2019
- **Autenticación**: Flask-Login
- **Frontend**: HTML5, CSS3, Bootstrap 5
- **Iconos**: Font Awesome
- **Conexión a BD**: pyodbc

## 📋 Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:

1. **Python 3.6 o superior**
   - Verifica tu versión con: `python --version`
   - Descarga desde [python.org](https://www.python.org/downloads/) si es necesario

2. **SQL Server**
   - SQL Server 2019 o superior recomendado
   - Puede ser Express Edition para desarrollo
   - Asegúrate de que el servicio esté en ejecución

3. **Herramientas de desarrollo**
   - Git para clonar el repositorio
   - Un editor de código (VS Code, PyCharm, etc.)

4. **Controladores ODBC para SQL Server**
   - Microsoft ODBC Driver for SQL Server
   - [Descargar desde Microsoft](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)

## 🚀 Instalación

### Clonar el Repositorio

1. Abre una terminal o línea de comandos
2. Navega al directorio donde deseas guardar el proyecto
3. Clona el repositorio con el siguiente comando:

```bash
git clone https://github.com/tu-usuario/sistema-video.git
cd sistema-video
