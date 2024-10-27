import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="sqluser",
  password="password"
)
mycursor=mydb.cursor()
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mycursor.execute("insert into test.test_table values(123,'Piyush', 123.4,123,'Naula')")
mydb.commit()
mydb.close()