[03-12-2025 09:16] Dinesh Enuguthala: 1. docker --version

2. docker pull hello-world

3. docker images ls

4. docker pull ubuntu

5. docker run -it ubuntu bash

6. echo "my image"

7. exit

8. docker ps -a

9. docker stop <id>

10. docker commit <container-id>

11. docker image ls

12. docker login

13. docker tag <source-image> vinithk8/ubuntu:latest

14. docker push vinithk8/ubuntu:latest


[03-12-2025 09:16] Dinesh Enuguthala: FROM alpine
RUN apk add --update redis
CMD ["redis-server"]


[03-12-2025 09:16] Dinesh Enuguthala: docker-compose.yml
docker-compose up -d
docker-compose down
docker-compose logs -f
docker-compose up --scale wordpress=2 -d
version: '3.8'

services:
  db:
    image: mysql:5.7
    container_name: mysql_db
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: wordpress
      MYSQL_USER: user
      MYSQL_PASSWORD: password
    volumes:
      - db_data:/var/lib/mysql

  wordpress:
    image: wordpress:latest
    container_name: wordpress_app
    restart: always
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: user
      WORDPRESS_DB_PASSWORD: password
      WORDPRESS_DB_NAME: wordpress
    depends_on:
      - db

volumes:
  db_data:
  
[03-12-2025 09:17] Dinesh Enuguthala: For NGINX (Alpine)

FROM nginx:alpine
COPY . /usr/share/nginx/html
[03-12-2025 09:17] Dinesh Enuguthala: Sudo docker build -t myapp .
Sudo docker run -d -p 80:80 myapp
