import mysql.connector
mydb = mysql.connector.connect(
    host="localhost",
    user="sqluser",
    password="password"
)
mycursor = mydb.cursor()
mycursor.execute(("select * from test.test_table"))
# mycursor.execute("select c1,c5 from test.test_table")
for i in mycursor.fetchall():
    print(i)
mydb.close()