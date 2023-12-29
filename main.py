from typing import Dict, Any
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, status, Request,Form,Header,APIRouter,Cookie
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse 
from fastapi.responses import JSONResponse,RedirectResponse,Response
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient 
from starlette.responses import Response
import string 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib 
from fastapi import Query
from starlette.responses import RedirectResponse
import random 
import secrets

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# MongoDB connection
myclient = MongoClient("mongodb://localhost:27017/")
mydb = myclient["myrealdatabase"]
users_col = mydb["user"]
students_col = mydb["student_details"]
# Create a counter collection to keep track of the latest ID
counters_col = mydb["counters"] 
messages_col = mydb["messages"]

def get_next_sequence_value(sequence_name):
    sequence_doc = counters_col.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"sequence_value": 1}},
        return_document=True,
        upsert=True,
    )
    return sequence_doc["sequence_value"]


# Update MongoDB collection schema
users_col.update_many({}, {"$set": {"course_registered": False}})

# Your existing JWT configuration
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

COOKIE_NAME = "access_token"

def hash_password(passwords: str):
    return pwd_context.hash(passwords)

def verify_password(passwords: str, hashed_password: str):
    return pwd_context.verify(passwords, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print("Error creating access token:")
        print(f"Data: {data}")
        print(f"Expires Delta: {expires_delta}")
        print(f"Exception: {e}")
        raise

# Modify the get_user function to print the username being searched
def get_user(username: str):
    print(f"Searching for user: {username}")
    Existing_username = users_col.find_one({'username': username})
    if not Existing_username:
        return False
    else:
        return Existing_username

#decode token
def decode_token(token: str) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials"
    )
    if token is None:
        return None

    # Remove leading and trailing whitespaces
    token = token.strip()

    # Check if the token starts with 'Bearer'
    if not token.startswith("Bearer"):
        raise credentials_exception

    try:
        # Extract the token without 'Bearer'
        token = token[len("Bearer"):].strip()
        print(f"Decoding token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded payload: {payload}")
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = get_user(username)
        return user
    except JWTError as e:
        print(f"Error decoding token: {e}")
        raise credentials_exception

# getting cookie for authentication
def get_current_user_from_cookie(request: Request) -> dict:
    try:
        token = request.cookies.get(COOKIE_NAME)
        print(f"Token from cookie: {token}")
        user_data = decode_token(token)
        if user_data is None:
            print("User data is None")
            return None
        return user_data
    except Exception as e:
        print(f"Error in get_current_user_from_cookie: {e}")
        return None

# Existing function to verify the password format
def is_valid_password(password):
    errors = []

    if len(password) < 8:
        errors.append("Password is too short") 
    if not any(char.isupper() for char in password):
        errors.append("Password doesn't contain an uppercase letter")

    if not any(char.islower() for char in password):
        errors.append("Password doesn't contain a lowercase letter")

    if not any(char in string.punctuation for char in password):
        errors.append("Password doesn't contain a special character")

    if not any(char.isdigit() for char in password):
        errors.append("Password doesn't contain a digit")

    return errors  # List of error messages, empty if password is valid

#login route 
@app.post("/login", response_class=HTMLResponse)
async def login_user(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    try:
        print(f"Login attempt - Username: {username}, Password: {password}")
        # Check if the user exists in the database
        existing_user = users_col.find_one({"username": username})
        print(f"Existing user: {existing_user}")

        if existing_user and pwd_context.verify(password, existing_user["password"]):
            print(f"Password verified - User: {existing_user['username']}")
            
            if existing_user.get("course_registered", False):
                # If the user is already registered, redirect to the "already_registered" template
                response = RedirectResponse(url=request.url_for("already_registered"))
                return response
            else:
                # If the user is not registered, proceed with the regular login flow
                access_token = create_access_token(data={"sub": username})
                print(f"Access Token: {access_token}")

                # Redirect to the home page
                response = RedirectResponse("/home", status_code=302)
                # Use the set_cookie method from RedirectResponse to set cookies
                response.set_cookie(key=COOKIE_NAME, value=f"Bearer {access_token}", httponly=True)
                return response
                
        else:    
            return templates.TemplateResponse("/login.html",{"request":request,"message":"Invalid Username or Password"})
            
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing parameter: {exc}")
    except Exception as exc:
        print(f"Error in login route: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error") from exc    


@app.get("/")
def read_form(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/login")
def read_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request}) 

@app.get("/loginsignup")
def read_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request}) 
  
@app.get("/signup", response_class = HTMLResponse)
def signup_form_route(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/home", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

# Email configuration
EMAIL_HOST = "your-smtp-host"
EMAIL_PORT = 587  # or the appropriate port for your SMTP server
EMAIL_USER = "vasavi1997.poluri@gmail.com"
EMAIL_PASSWORD = "gsyi coaw ekpm udqv"

def send_otp_email(email: str, otp: str):
    sender_email = "vasavi1997.poluri@gmail.com"  
    receiver_email = email
    password = "gsyi coaw ekpm udqv"  

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Password Reset OTP"

    body = f"Your OTP for password reset: {otp}"
    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

@app.post("/generate-otp")
async def generate_otp(request:Request, username: str = Form(...)):
    # Check if user exists in the database
    existing_user = users_col.find_one({"username": username})

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Using the "username" as the email value
    email = existing_user["username"]
    # Generate a 6-digit OTP (for demonstration purposes)
    otp = str(random.randint(100000, 999999))

    # Save the OTP in the user document in the database
    users_col.update_one({"username": username}, {"$set": {"otp": otp}})

    # Send the OTP to the user's email
    send_otp_email(email ,otp)

    return templates.TemplateResponse("enter-otp.html",{"request":request, "message": "OTP generated and sent successfully"})


@app.post("/verify-and-update")
def verify_and_update(
    request: Request,
    username: str = Form(...),
    otp: str = Form(...),
    newpassword: str = Form(...),
):
    try:
        # Retrieve the OTP generated during the "generate-otp" step
        existing_user = users_col.find_one({"username": username})
        stored_otp = existing_user.get("otp", None)

        hashed_password = pwd_context.hash(newpassword)

        if stored_otp is not None and otp == stored_otp:
            # Update the password in the database
            users_col.update_one({"username": username}, {"$set": {"password": hashed_password}})

            # Optionally, you can remove the OTP field after updating the password
            users_col.update_one({"username": username}, {"$unset": {"otp": ""}})

            return templates.TemplateResponse("login.html", {"request": request, "message": "Password updated successfully"})
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP")

    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/signup", response_class=HTMLResponse)
async def signup(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_repeat: str = Form(...),
   
):
    try:
        # Check if the user already exists
        existing_user = users_col.find_one({"username": username})
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")

        if password != password_repeat:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        password_validation_errors = is_valid_password(password)

        if password_validation_errors:
            return templates.TemplateResponse("signup.html", {"request": request, "error_messages": password_validation_errors}) 
        
        hashed_password = pwd_context.hash(password)

        # Get the next available ID from the counter
        common_id = get_next_sequence_value("common_id") 
        
        users_col.insert_one({"_id": common_id, "username": username, "password": hashed_password})

        return templates.TemplateResponse("login.html", {"request": request, "message": "User Created Successfully!"})
    
    except HTTPException as e:
        print(f"Caught HTTPException: {e}")
        return templates.TemplateResponse("signup.html", {"request": request, "error_messages": [e.detail]})
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        return templates.TemplateResponse("signup.html", {"request": request, "error_messages": ["Internal Server Error"]}) 

@app.post("/registration", response_class=HTMLResponse)
def register_student(
    request: Request,
    firstname: str = Form(...),
    lastname: str = Form(...),
    dateofbirth: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    collegename: str = Form(...),
    degree: str = Form(...),
    course: str = Form(...),
    current_user: dict = Depends(get_current_user_from_cookie)
):
    try:
        # Check if the user is authenticated
        if not current_user or not current_user.get('username'):
            raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")

        # Check if the student is already registered for the course
        existing_registration = students_col.find_one({"email": email, "course_registered": True})
        if existing_registration:
            # Student is already registered, redirect to a page with a message
            return templates.TemplateResponse("already_registered.html", {"request": request, "user": current_user.get('username')})

        # Check if the user has already registered for the course using the current username
        existing_user_registration = students_col.find_one({"email": current_user.get('username'), "course_registered": True})
        if existing_user_registration:
            # User is already registered, redirect to a page with a message
            return templates.TemplateResponse("already_registered.html", {"request": request, "user": current_user.get('username')})
        
        # Get the next available ID from the counter
        common_id = get_next_sequence_value("common_id")

        # Insert the student data into the MongoDB collection
        student_data = {
            "_id": common_id,
            "firstname": firstname,
            "lastname": lastname,
            "dateofbirth": dateofbirth,
            "email": email,
            "phone": phone,
            "collegename": collegename,
            "degree": degree,
            "course": course,
            "course_registered": True,  # Set course registration status to True
        }
        result = students_col.insert_one(student_data)

        # Check if the insertion was successful
        if result.inserted_id:
            # Update the user document to indicate course registration
            users_col.update_one({"username": current_user.get('username')}, {"$set": {"course_registered": True}})
            print(f"Update Result: {result}")
            # Retrieve the updated user data
            user_data = students_col.find()
            
            return templates.TemplateResponse("studentdetails.html", {"request": request, "user_data": user_data, "user": current_user.get('username')})
        else:
            raise HTTPException(status_code=500, detail="Failed to insert data into MongoDB")

    except HTTPException as e:
        # Pass the exception details to the template
        return templates.TemplateResponse("studentdetails.html", {"request": request, "message": f"Error: {e.detail}"})

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Pass the exception details to the template
        return templates.TemplateResponse("studentdetails.html", {"request": request, "message": "Internal Server Error"})

@app.get("/courses", response_class=HTMLResponse)
def dashboard(request: Request, current_user: dict = Depends(get_current_user_from_cookie)):
    # Check if the user is authenticated
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
    
    return templates.TemplateResponse("courses.html", {"request": request, "user": current_user.get('username')})

@app.get("/registration", response_class=HTMLResponse)
def dashboard(request: Request, current_user: dict = Depends(get_current_user_from_cookie)):
    # Check if the user is authenticated
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
    return templates.TemplateResponse("registration.html", {"request": request, "user": current_user.get('username')})

@app.get("/studentdetails", response_class=HTMLResponse)
def dashboard(request: Request, current_user: dict = Depends(get_current_user_from_cookie)):
    # Check if the user is authenticated
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
    user_data = students_col.find()
    return templates.TemplateResponse("studentdetails.html", {"request": request,"user": current_user.get('username'), "user_data": user_data}) 

@app.get("/student/{common_id}", response_class=JSONResponse)
def get_student_details(request:Request,common_id: int, current_user: dict = Depends(get_current_user_from_cookie)):
    try: 
        # Check if the user is authenticated
        if not current_user or not current_user.get('username'):
            raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
        # Find the student by ID in the MongoDB collection
        student = students_col.find_one({"_id": common_id})

        if student:
            # Return the student details as a JSON response
            return JSONResponse(content={"student": student,"user": current_user.get('username')})
        else:
            # If the student ID is not found, return a 404 Not Found response
            raise HTTPException(status_code=404, detail="Student not found")

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Return a 500 Internal Server Error response
        raise HTTPException(status_code=500, detail="Internal Server Error") 
    
@app.get("/edit-student/{common_id}", response_class=HTMLResponse)
def edit_student_form(request: Request, common_id: int, current_user: dict = Depends(get_current_user_from_cookie)):
    # Check if the user is authenticated
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
    # Retrieve the student details by ID
    student = students_col.find_one({"_id": common_id})

    # Check if the current user is the owner of the course registration
    if student["email"] != current_user.get('username'):
        raise HTTPException(status_code=403, detail="Forbidden: You don't have permission to edit this course registration")

    # Render the edit form with existing student details
    return templates.TemplateResponse("edit_student.html", {"request": request,"user": current_user.get('username'), "student": student})

@app.post("/edit-student/{common_id}")
async def edit_student(
    request: Request,
    common_id: int,
    current_user: dict = Depends(get_current_user_from_cookie),
    firstname: str = Form(...),
    lastname: str = Form(...),
    dateofbirth: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    collegename: str = Form(...),
    degree: str = Form(...),
    course: str = Form(...),
):
    try:
        # Check if the user is authenticated
        if not current_user or not current_user.get('username'):
            raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")

        # Check if the current user is the owner of the course registration
        student = students_col.find_one({"_id": common_id})
        if student["email"] != current_user.get('username'):
            raise HTTPException(status_code=403, detail="Forbidden: You don't have permission to edit this course registration")

        # Construct the updated_data dictionary
        updated_data = {
            "firstname": firstname,
            "lastname": lastname,
            "dateofbirth": dateofbirth,
            "email": email,
            "phone": phone,
            "collegename": collegename,
            "degree": degree,
            "course": course,
        }

        # Update the student details in the database
        students_col.update_one({"_id": common_id}, {"$set": updated_data})

        # Redirect to the student details page after editing
        return RedirectResponse(url="/studentdetails", status_code=302)


    except Exception as e:
        # Handle unexpected exceptions
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/reset", response_class=HTMLResponse)
def reset_password_view(request: Request):
    return templates.TemplateResponse("reset.html", {"request": request})

@app.post("/delete-student/{common_id}")
def delete_student(request:Request,common_id: int,current_user: dict = Depends(get_current_user_from_cookie)):
    # Check if the user is authenticated
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
        
    # Check if the current user is the owner of the course registration
    student = students_col.find_one({"_id": common_id})
    if student["email"] != current_user.get('username'):
        raise HTTPException(status_code=403, detail="Forbidden: You don't have permission to delete this course registration")

    # Delete the student record from the database
    students_col.delete_one({"_id": common_id})

    # Redirect to the student details page after deleting 
    return RedirectResponse(url="/studentdetails", status_code=302)           
    3

@app.get("/contactus", response_class=HTMLResponse)
def dashboard(request: Request, current_user: dict = Depends(get_current_user_from_cookie)):
    # Check if the user is authenticated
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")

    return templates.TemplateResponse("contactus.html", {"request": request, "user": current_user.get('username')}) 

@app.get("/privacypolicy", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("privacypolicy.html", {"request": request}) 

@app.get("/termsofservices", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("termsofservices.html", {"request": request})

@app.post("/submit-form")
def submit_form(request: Request,
    message: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),current_user: dict = Depends(get_current_user_from_cookie)
):
    if not current_user or not current_user.get('username'):
        raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")
    # Insert the form data into the MongoDB collection
    result = messages_col.insert_one({"message": message, "name": name, "email": email}) 
    return templates.TemplateResponse("contactus.html",{"request":request,"user": current_user.get('username'),"message":"Message sent successfully!"})

    # return {"status": "success", "message": "Form submitted successfully", "document_id": str(result.inserted_id)}

@app.get("/logout")
def logout_get(response: Response):
    try:
        redirect_response = RedirectResponse(url="/login")
        redirect_response.delete_cookie(COOKIE_NAME)
        return redirect_response
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="Cookie name not found.") from exc
    except Exception as exception:
        raise HTTPException(status_code=500, detail=str(exception)) from exception 


@app.get("/student/{common_id}", response_class=JSONResponse)
def get_student_details(
    request: Request,
    common_id: int,
    firstname: str = Query(None, description="Filter students by first name"),
    current_user: dict = Depends(get_current_user_from_cookie)
):
    try:
        # Check if the user is authenticated
        if not current_user or not current_user.get('username'):
            raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")

        # Build the query based on the first name, if provided
        query = {"_id": common_id}
        if firstname:
            query["firstname"] = firstname  # Use "firstname" as the MongoDB field name

        # Find the student by ID and optional first name filter in the MongoDB collection
        student = students_col.find_one(query)

        if student:
            # Return the student details as a JSON response
            return JSONResponse(content={"student": student, "user": current_user.get('username')})
        else:
            # If the student ID is not found, return a 404 Not Found response
            raise HTTPException(status_code=404, detail="Student not found")

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Return a 500 Internal Server Error response
        raise HTTPException(status_code=500, detail="Internal Server Error") 
    
@app.get("/student/{common_id}", response_class=JSONResponse)
def get_student_details(
    request: Request,
    common_id: int,
    firstname: str = Query(None, description="Filter students by first name"),
    current_user: dict = Depends(get_current_user_from_cookie)
):
    try:
        # Check if the user is authenticated
        if not current_user or not current_user.get('username'):
            raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")

        # Build the query based on the first name, if provided
        query = {"_id": common_id}
        if firstname:
            query["firstname"] = firstname  # Use "firstname" as the MongoDB field name

        # Find the student by ID and optional first name filter in the MongoDB collection
        student = students_col.find_one(query)

        if student:
            # Return the student details as a JSON response
            return JSONResponse(content={"student": student, "user": current_user.get('username')})
        else:
            # If the student ID is not found, return a 404 Not Found response
            raise HTTPException(status_code=404, detail="Student not found")

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Return a 500 Internal Server Error response
        raise HTTPException(status_code=500, detail="Internal Server Error") 


@app.get("/student/{common_id}", response_class=JSONResponse)
def get_student_details(
    request: Request,
    common_id: int,
    current_user: dict = Depends(get_current_user_from_cookie),
    **kwargs: str
):
    try:
        # Check if the user is authenticated
        if not current_user or not current_user.get('username'):
            raise HTTPException(status_code=401, detail="Unauthorized access. Please log in.")

        # Build the query based on the received query parameters
        query = {"_id": common_id}
        for key, value in kwargs.items():
            query[key] = value

        # Find the student by ID and optional filters in the MongoDB collection
        student = students_col.find_one(query)

        if student:
            # Return the student details as a JSON response
            return JSONResponse(content={"student": student, "user": current_user.get('username')})
        else:
            # If the student ID is not found, return a 404 Not Found response
            raise HTTPException(status_code=404, detail="Student not found")

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Return a 500 Internal Server Error response
        raise HTTPException(status_code=500, detail="Internal Server Error")

