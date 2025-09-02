# build image

docker build -t <image_name> .

# run container

docker run -d --name <container_name>  --restart unless-stopped  --memory 512m --cpus 1 -p <local_port>:6080 <image_name>

