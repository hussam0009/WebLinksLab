docker build -t mysql_db .

docker run -d --name my_mysql_container -p 3306:3306 mysql_db

