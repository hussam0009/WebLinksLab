from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response, Form, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import sqlite3
import jwt
from datetime import datetime, timedelta
import os
from passlib.context import CryptContext
from passlib.exc import UnknownHashError
from fastapi.middleware.cors import CORSMiddleware
import logging
from dotenv import load_dotenv
import httpx
import asyncio
import docker 
import random
import socket
import subprocess
import uuid
from docker.errors import DockerException
import mysql.connector
from mysql.connector import Error
import time 
from typing import Optional

load_dotenv()

# Add lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting application...")
    yield
    # Shutdown
    logger.info("Shutting down gracefully...")

app = FastAPI(lifespan=lifespan)

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")


# CORS Configuration
origins = [
    "http://localhost:5000",
    "chrome-extension://fokomikcibdhbkpgmdiieengclhblhgl"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Secret Key
SECRET_KEY = os.getenv('SECRET_KEY')
# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database Setup

def wait_for_mysql(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD
            )
            conn.close()
            print("✅ MySQL is ready.")
            return
        except mysql.connector.Error as err:
            print(f"⏳ Waiting for MySQL: {err}")
            time.sleep(2)
    raise RuntimeError("❌ MySQL did not become ready in time.")

def check_database():
    found_database = False
    found_container = False

    local_docker = docker.from_env()

    # Check if the image exists
    images = local_docker.images.list()
    for image in images:
        if any('weblinkslab_db' in tag for tag in image.tags):
            print(f"Found matching image: {image.id}")
            print("Tags:", image.tags)
            found_database = True
            break

    # Build the image if not found
    if not found_database:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Database")
        print("Building database image, please wait...")
        local_docker.images.build(
            path=db_path,
            dockerfile='Dockerfile',
            tag='weblinkslab_db:latest',
            rm=True
        )
        print("Database image built successfully.")

    # Check for a running container
    containers = local_docker.containers.list(all=True)
    for container in containers:
        if container.name.startswith("weblinkslab_db"):
            if container.status == "running":
                found_container = True
                print(f"Found running container: {container.name}")
            else:
                print(f"Starting existing container: {container.name}")
                container.start()
                found_container = True
            break

    # Run the container if not found
    if not found_container:
        print("No existing container found. Running new container...")
        local_docker.containers.run(
            'weblinkslab_db:latest',
            name="weblinkslab_db_container",
            ports={"3306/tcp": 3306},
          detach=True,
        )

    local_docker.close()
    wait_for_mysql()

check_database()
def init_db():

    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        conn.database = DB_NAME
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
                 CREATE TABLE IF NOT EXISTS user_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                action_type ENUM('scan_url', 'deploy_container') NOT NULL,
                ContainerID VARCHAR(64) NULL DEFAULT NULL,
                description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"⏳ Waiting for MySQL: {err}")
        time.sleep(2)
    except Error as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

init_db()
#Add host key

Remote=os.getenv("Remote")

try:
    # Run ssh-keyscan and check for success
    keyscan_result = subprocess.run(
        ["ssh-keyscan", "-H", Remote],
        check=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    
    # Append to known_hosts only if successful
    with open(os.path.expanduser("~/.ssh/known_hosts"), "a") as f:
        f.write(keyscan_result.stdout)
    
except subprocess.CalledProcessError as e:
    raise RuntimeError(f"SSH keyscan failed: {e.stderr}") from e
except Exception as e:
    raise RuntimeError(f"Unexpected error during keyscan: {str(e)}") from e

try:
    # Create Docker client with connection timeout
    client = docker.DockerClient(
        base_url=f"ssh://top0z@{Remote}",
        timeout=10
    )
    
    # Verify connection by making a simple API call
    client.ping()
    REMOTE_HOST = f"top0z@{Remote}"

except DockerException as e:
    raise RuntimeError(f"Docker connection failed: {str(e)}") from e
except Exception as e:
    raise RuntimeError(f"Unexpected error with Docker client: {str(e)}") from e


# Utility Functions
def get_user_by_username(username: str):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user
    except Error as e:
        logger.error(f"Database query failed: {str(e)}")
        raise


def create_user(username: str, password: str):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        hashed_password = pwd_context.hash(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered")
    except Error as e:
        logger.error(f"Database insertion failed: {str(e)}")
        raise


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(username: str):
    return jwt.encode(
        {"username": username, "exp": datetime.utcnow() + timedelta(hours=1)},
        SECRET_KEY,
        algorithm="HS256"
    )

def get_available_port(start=1000, end=60000):
    try:
        containers = client.containers.list(all=True)
        
        # Get all ports used by Docker containers
        used_ports = set()
        for container in containers:
            for port_config in container.attrs['NetworkSettings']['Ports'].values():
                if port_config:
                    used_ports.add(int(port_config[0]['HostPort']))

        # Get ports in use on remote host using SSH check
        def is_port_free(port):
            result = subprocess.run(
                ['ssh', REMOTE_HOST, f"python3 -c 'import socket; s=socket.socket(); s.settimeout(0.5); exit(1 if s.connect_ex((\"\", {port})) == 0 else 0)'"],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            return result.returncode == 0

        ports = list(range(start, end))
        random.shuffle(ports)
        for port in ports:
            if port in used_ports:
                continue
            if not is_port_free(port):
                continue
            if not any(str(port) in cont.name for cont in containers):
                return port
                
        raise RuntimeError("No available ports found.")
    except Exception as e:
        print("error found", e)

async def get_virustotal_stats(url: str):
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")

    async with httpx.AsyncClient() as client:
        try:
            # Submit URL to VirusTotal
            submit_response = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": api_key},
                data={"url": url}
            )
            submit_response.raise_for_status()
            
            # Get analysis ID
            analysis_id = submit_response.json()['data']['id']
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            # Poll for results with async sleep
            for _ in range(5):
                analysis_response = await client.get(
                    analysis_url,
                    headers={"x-apikey": api_key}
                )
                analysis_response.raise_for_status()
                
                result = analysis_response.json()
                if result['data']['attributes']['status'] == 'completed':
                    return result['data']['attributes']['stats']
                
                await asyncio.sleep(10)  # Async sleep

            raise HTTPException(status_code=504, detail="VirusTotal scan timeout")

        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"VirusTotal API error: {e.response.text}"
            )
        except asyncio.CancelledError:
            raise HTTPException(status_code=503, detail="Service shutting down")

def save_user_history(user_id: int, action_type: str,  ContainerID: str ="" ,description: str = ""):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        if (action_type == "deploy_container"):
             cursor.execute('''
            INSERT INTO user_history (user_id, action_type, ContainerID, description)
            VALUES (%s, %s ,%s , %s)
        ''', (user_id, action_type ,ContainerID, description))
        else:
            cursor.execute('''
                INSERT INTO user_history (user_id, action_type, description)
                VALUES (%s, %s, %s)
            ''', (user_id, action_type, description))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        logger.error(f"Failed to save user history: {str(e)}")
        raise

def get_active_containers(user_containers: list) -> list:

    active_containers = []
    
    try:        
        # Get all running containers with their IDs
        running_containers = {container.id for container in client.containers.list()}
        # Check each container in user's list against running containers
        active_containers=[container for container in user_containers if container in running_containers]
                
    except DockerException as e:
        print(f"Docker error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        
    return active_containers

# Pydantic Models for Request and Response
class User(BaseModel):
    username: str
    password: str

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle missing username/password at the framework level"""
    errors = exc.errors()
    for error in errors:
        if any(field in error['loc'] for field in ('username', 'password')):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Both username and password are required"},
            )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


@app.post("/api/register")
async def register(user: User):
    existing_user = get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    create_user(user.username, user.password)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"message": "User successfully registered!"}
    )

@app.post("/api/login")
async def login(
    response: Response,
    username: str = Form(..., min_length=1, max_length=50),
    password: str = Form(..., min_length=1, max_length=50)
):
    try:
        # Validate empty credentials after stripping whitespace
        if not username.strip() or not password.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and password cannot be empty or whitespace only"
            )

        # Database operation with error handling
        try:
            user = get_user_by_username(username)
        except sqlite3.Error as e:
            logger.error(f"Database error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable"
            )

        # Timing attack protection
        stored_hash = user[2] if user else pwd_context.hash("dummy_password")
        
        # Password verification with error handling
        try:
            password_valid = pwd_context.verify(password, stored_hash)
        except (ValueError, UnknownHashError) as e:
            logger.error(f"Password verification error: {str(e)}")
            password_valid = False

        if not (user and password_valid):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Token generation with error handling
        try:
            token = create_access_token(username)
        except jwt.PyJWTError as e:
            logger.error(f"JWT error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token generation failed"
            )

        # Set secure cookie
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Login successful"}
        )
        response.set_cookie(
            key="token",
            value=token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=3600  # 1 hour expiration
        )
        return response

    except HTTPException as he:
        # Re-raise properly typed exceptions
        raise
    except Exception as e:
        logger.critical(f"Unexpected error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred"
        )
@app.get("/api/dashboard")
async def dashboard(request: Request):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Token is missing")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user_by_username(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT action_type,description,timestamp FROM user_history
            WHERE user_id = %s AND action_type= %s
            ORDER BY timestamp DESC
        ''', (user[0],"scan_url"))
        scan_url = cursor.fetchall()
        cursor.execute('''
            SELECT ContainerID FROM user_history
            WHERE user_id = %s
            ORDER BY timestamp DESC
        ''', (user[0],))
        user_containers=[row['ContainerID'] for row in cursor.fetchall()]
        active_containers=get_active_containers(user_containers)
        running_containers=[]
        for container_id in active_containers:
            cursor.execute('''
                SELECT * FROM user_history
                WHERE ContainerID = %s
                ORDER BY timestamp DESC
            ''', (container_id,))
            running_containers.extend(cursor.fetchall())
        cursor.close()
        conn.close()
        for entry in scan_url:
            if isinstance(entry['timestamp'], datetime):
                entry['timestamp'] = entry['timestamp'].isoformat()
        for entry in running_containers:
            if isinstance(entry['timestamp'], datetime):
                entry['timestamp'] = entry['timestamp'].isoformat()
        return {
            "username": user[1],
            "user_id": user[0],
            "scan_url": scan_url,
            "running_containers":running_containers
        }
    except Error as e:
        logger.error(f"Failed to fetch dashboard history: {str(e)}")
        return {
            "username": user[1],
            "user_id": user[0],
            "history": []
        }
    


# Modified scan endpoint

@app.api_route("/api/scan_url", methods=["GET", "POST"])
async def scan_url(
    request: Request,
    url: Optional[str] = Form(None)
):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Token is missing")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user_by_username(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if request.method == "POST":
        if not url:
            raise HTTPException(status_code=400, detail="URL is required in POST request")

        try:
            result = await get_virustotal_stats(url)
            save_user_history(user[0], "scan_url","Null", f"Scanned URL: {url}")
            return result
        except HTTPException as he:
            raise he
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    elif request.method == "GET":
        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT action_type,description,timestamp FROM user_history
                WHERE user_id = %s AND action_type = %s
                ORDER BY timestamp DESC
            ''', (user[0],"scan_url"))
            history = cursor.fetchall()
            cursor.close()
            conn.close()

            # Convert datetime objects to ISO format strings
            for entry in history:
                if isinstance(entry['timestamp'], datetime):
                    entry['timestamp'] = entry['timestamp'].isoformat()

            return JSONResponse({"history": history})

        except Error as e:
            logger.error(f"Failed to fetch scan history: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to retrieve scan history")

    elif request.method == "GET":
        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT * FROM user_history
                WHERE user_id = %s AND action_type = 'scan_url'
                ORDER BY timestamp DESC
            ''', (user[0],))
            history = cursor.fetchall()
            cursor.close()
            conn.close()
            return JSONResponse({"history": history})
        except Error as e:
            raise HTTPException(status_code=500, detail="Failed to retrieve scan history")
    

@app.get("/api/deploy_container")
async def deploy_container(request: Request,):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Token is missing")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user_by_username(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        port = get_available_port()
        container = client.containers.run(
            "dev-chrome1",
            detach=True,
            ports={"6080/tcp": port},  # Explicit TCP port
            name=f"instance_{port}_{uuid.uuid4().hex[:6]}",  # Unique name
            remove=True  # Auto-remove if stopped
        )
        url=f"http://{Remote}:{port}"
        save_user_history(user[0], "deploy_container",container.id, f"Container url: {url}")
        return JSONResponse({
            "status": "success",
            "port": port,
            "container_id": container.id,
            "access_url": url
        })
        
    except docker.errors.DockerException as e:
        return JSONResponse(
            {"status": "error", "message": f"Docker error: {str(e)}"},
            status_code=500
        )
    except Exception as e:
        return JSONResponse(
            {"status": "error", "message": f"Server error: {str(e)}"},
            status_code=500
        )

@app.post("/api/delete_container")
async def delete_container(request: Request,container_id: str = Form(...)):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Token is missing")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user_by_username(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        container = client.containers.get(container_id)
        container.remove(force=True)
        return {"delete_container": "Container deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete container: {str(e)}")
    
@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="token")
    return {"message": "Logged out successfully"}


