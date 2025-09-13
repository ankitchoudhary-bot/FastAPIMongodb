"""
FastAPI + MongoDB Assessment

How to run:
1. Ensure MongoDB is running locally (default: mongodb://localhost:27017).
2. Create virtualenv and install requirements: `pip install fastapi uvicorn pymongo`
3. Run: `uvicorn main:app --reload --port 8000`

This single-file app implements the required endpoints for the assessment:
- POST   /employees            -> create employee (employee_id unique)
- GET    /employees/{employee_id} -> fetch by employee_id (404 if missing)
- PUT    /employees/{employee_id} -> partial update (only provided fields)
- DELETE /employees/{employee_id} -> delete employee
- GET    /employees?department=..&page=&size=  -> list by department sorted by joining_date (newest first) + pagination
- GET    /employees/avg-salary -> aggregation: average salary by department
- GET    /employees/search?skill=Python -> search employees who have the given skill

Notes:
- joining_date expected in 'YYYY-MM-DD' format; stored in MongoDB as a datetime.
- A unique index on employee_id is created at startup.

"""
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from fastapi import FastAPI, HTTPException, status, Query, Depends
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timedelta
import os

# ---------- JWT Setup ----------
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login", scheme_name="JWT")

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fake user store (for demo, replace with Mongo collection later)
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123")  # password = admin123
    }
}


def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        return None
    if not pwd_context.verify(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------- Configuration ----------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "assessment_db")
COLLECTION_NAME = os.getenv("MONGO_COLLECTION", "employees")

app = FastAPI(title="Employees Assessment API")

# Create client (synchronous pymongo for simplicity in this assessment)
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# ---------- MongoDB Setup ----------
# Ensure collection with schema validation
validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["employee_id", "name", "department", "salary", "joining_date"],
        "properties": {
            "employee_id": {
                "bsonType": "string",
                "description": "must be a string and is required"
            },
            "name": {
                "bsonType": "string",
                "description": "must be a string and is required"
            },
            "department": {
                "bsonType": "string",
                "description": "must be a string and is required"
            },
            "salary": {
                "bsonType": "number",
                "minimum": 0,
                "description": "must be a positive number and is required"
            },
            "joining_date": {
                "bsonType": "date",
                "description": "must be a valid date and is required"
            },
            "skills": {
                "bsonType": "array",
                "items": {
                    "bsonType": "string"
                },
                "description": "must be an array of strings"
            }
        }
    }
}

try:
    db.create_collection(COLLECTION_NAME, validator=validator)
except Exception as e:
    # If already exists, update validator
    db.command("collMod", COLLECTION_NAME, validator=validator)

collection = db[COLLECTION_NAME]

# Ensure unique index on employee_id
collection.create_index([("employee_id", ASCENDING)], unique=True)

# ---------- Pydantic models ----------
class EmployeeBase(BaseModel):
    name: Optional[str] = None
    department: Optional[str] = None
    salary: Optional[float] = None
    joining_date: Optional[str] = None  # 'YYYY-MM-DD'
    skills: Optional[List[str]] = None

class EmployeeCreate(EmployeeBase):
    employee_id: str = Field(..., min_length=1)

class EmployeeUpdate(EmployeeBase):
    pass

class EmployeeOut(EmployeeCreate):
    # For simplicity we mirror input fields for output; joining_date will be returned as 'YYYY-MM-DD' string
    pass

# ---------- Helpers ----------

def _parse_joining_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="joining_date must be in YYYY-MM-DD format")


def _doc_to_response(doc: Dict[str, Any]) -> Dict[str, Any]:
    # Convert MongoDB document to JSON-serializable dict matching EmployeeOut
    return {
        "employee_id": doc.get("employee_id"),
        "name": doc.get("name"),
        "department": doc.get("department"),
        "salary": doc.get("salary"),
        "joining_date": doc.get("joining_date").strftime("%Y-%m-%d") if doc.get("joining_date") else None,
        "skills": doc.get("skills", []),
    }

# ---------- Endpoints ----------

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/employees", response_model=EmployeeOut, status_code=status.HTTP_201_CREATED)
def create_employee(payload: EmployeeCreate, username: str = Depends(get_current_user)):
    # Prepare document
    doc = payload.dict()
    jd = doc.pop("joining_date", None)
    if jd:
        doc["joining_date"] = _parse_joining_date(jd)
    # Insert
    try:
        collection.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="employee_id must be unique")
    created = collection.find_one({"employee_id": payload.employee_id})
    return _doc_to_response(created)


@app.get("/employees", response_model=List[EmployeeOut])
def list_employees(department: Optional[str] = Query(None), page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=100)):
    query = {}
    if department:
        query["department"] = department
    skip = (page - 1) * size
    cursor = collection.find(query).sort("joining_date", -1).skip(skip).limit(size)
    return [_doc_to_response(d) for d in cursor]


@app.get("/employees/avg-salary")
def avg_salary_by_department():
    pipeline = [
        {"$group": {"_id": "$department", "avg_salary": {"$avg": "$salary"}}},
        {"$project": {"_id": 0, "department": "$_id", "avg_salary": {"$round": ["$avg_salary", 2]}}},
        {"$sort": {"department": 1}}
    ]
    res = list(collection.aggregate(pipeline))
    return res

@app.get("/employees/search", response_model=List[EmployeeOut])
def search_employees_by_skill(skill: str = Query(..., min_length=1)):
    cursor = collection.find({"skills": {"$in": [skill]}}).sort("joining_date", -1)
    return [_doc_to_response(d) for d in cursor]


@app.get("/employees/{employee_id}", response_model=EmployeeOut)
def get_employee(employee_id: str):
    doc = collection.find_one({"employee_id": employee_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Employee not found")
    return _doc_to_response(doc)


@app.put("/employees/{employee_id}", response_model=EmployeeOut)
def update_employee(employee_id: str, payload: EmployeeUpdate, username: str = Depends(get_current_user)):
    update_fields = {k: v for k, v in payload.dict().items() if v is not None}
    if not update_fields:
        raise HTTPException(status_code=400, detail="No fields provided for update")
    if "joining_date" in update_fields:
        update_fields["joining_date"] = _parse_joining_date(update_fields["joining_date"])
    result = collection.update_one({"employee_id": employee_id}, {"$set": update_fields})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found")
    doc = collection.find_one({"employee_id": employee_id})
    return _doc_to_response(doc)


@app.delete("/employees/{employee_id}")
def delete_employee(employee_id: str, username: str = Depends(get_current_user)):
    result = collection.delete_one({"employee_id": employee_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found")
    return {"message": "Employee deleted successfully"}


# ---------- Optional: simple healthcheck ----------
@app.get("/health")
def health_check():
    try:
        # ping the server
        client.admin.command("ping")
        return {"status": "ok"}
    except Exception:
        raise HTTPException(status_code=503, detail="Cannot connect to MongoDB")
