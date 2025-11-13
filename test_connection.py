import pymysql

def get_db_connection():
    try:
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password='Neeru705',
            database='banking',
            cursorclass=pymysql.cursors.DictCursor
        )
        print("✅ Connection to the database was successful.")
        connection.close()
    except Exception as e:
        print(f"❌ Connection failed: {e}")

get_db_connection()

