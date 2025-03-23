import pyodbc

conn_str = "DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=Inveing;Trusted_Connection=yes;"
try:
    conn = pyodbc.connect(conn_str)
    print("✅ Conexión exitosa a SQL Server")
except Exception as e:
    print("❌ Error de conexión:", e)
