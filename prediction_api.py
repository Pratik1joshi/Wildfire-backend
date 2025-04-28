# At the top of the file, import async SQLAlchemy components
from fastapi import FastAPI, HTTPException, Path, Depends, status, Query, Request, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import pandas as pd
import logging
from datetime import datetime, date, timedelta
import re
import secrets
from passlib.context import CryptContext
import os
import json
import tempfile
import io
from dotenv import load_dotenv
import uvicorn

load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("prediction_api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("prediction_api")

# Create FastAPI app
app = FastAPI(title="LiveFire Prediction API", 
              description="API for accessing wildfire predictions and user management",
              version="1.0.0")

# Add CORS middleware with specific origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://wildfire-frontend-mp31.vercel.app", "https://wildfire-frontend-mp31-pr5f9a2ig-pratik-joshis-projects.vercel.app"  # Add this for local development
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
    expose_headers=["Content-Type", "Authorization"],
)

# Database connection
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql+asyncpg://neondb_owner:npg_5CebzT3QoMpH@ep-dawn-mud-a1f9ydb7-pooler.ap-southeast-1.aws.neon.tech/neondb"
)

# For asyncpg, the ssl parameter should be simply True or an SSL context
ENGINE = create_async_engine(
    DATABASE_URL,
    connect_args={"ssl": True},
    pool_size=5,  # Add connection pool settings
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800
)

async_session = sessionmaker(
    ENGINE,
    expire_on_commit=False,
    class_=AsyncSession
)

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,  # Adjust the number of rounds as needed
)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# -------------------- Models --------------------

class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    role: str = "user"

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class PredictionResponse(BaseModel):
    latitude: float
    longitude: float
    prediction_date: str
    fire_prob: float
    fire_category: str
    gapa_napa: Optional[str] = None
    district: Optional[str] = None
    pr_name: Optional[str] = None
    province: Optional[float] = None

class AlertBase(BaseModel):
    title: str
    message: str
    level: str  # "info", "warning", "danger"
    location: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: int
    created_at: datetime
    is_active: bool
    
    class Config:
        orm_mode = True

class PredictionStats(BaseModel):
    total_predictions: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    minimal_risk_count: int
    date_range: Dict[str, str]
    top_risk_areas: List[Dict[str, Any]]

# -------------------- Authentication Functions --------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user_by_email(email: str):
    query = text("""
    SELECT id, email, full_name, hashed_password, role, created_at
    FROM users
    WHERE email = :email
    """)
    
    async with async_session() as session:
        result = await session.execute(query, {"email": email})
        user = result.fetchone()
        
        if user:
            return {
                "id": user[0],
                "email": user[1],
                "full_name": user[2],
                "hashed_password": user[3],
                "role": user[4],
                "created_at": user[5]
            }
        return None

async def authenticate_user(email: str, password: str):
    user = await get_user_by_email(email)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def generate_token():
    return secrets.token_hex(32)

# -------------------- Authentication Routes --------------------

@app.post("/auth/signup", response_model=Token)
async def signup(user: UserCreate):
    # Check if user already exists
    existing_user = await get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Insert new user
    query = text("""
    INSERT INTO users (email, full_name, hashed_password, role, created_at)
    VALUES (:email, :full_name, :hashed_password, :role, NOW())
    RETURNING id, email, full_name, role, created_at
    """)
    
    try:
        async with async_session() as session, session.begin():
            result = await session.execute(
                query, 
                {
                    "email": user.email,
                    "full_name": user.full_name,
                    "hashed_password": hashed_password,
                    "role": user.role
                }
            )
            new_user = result.fetchone()
            
            if not new_user:
                raise HTTPException(status_code=500, detail="Failed to create user")
                
            # Generate token
            token = generate_token()
            
            # Return response
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": new_user[0],
                    "email": new_user[1],
                    "full_name": new_user[2],
                    "role": new_user[3],
                    "created_at": new_user[4]
                }
            }
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate token
    token = generate_token()
    
    # Return token and user info
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "created_at": user["created_at"]
        }
    }

# -------------------- Prediction Routes --------------------

@app.get("/predictions/{date}/{model}", response_model=List[PredictionResponse])
async def get_predictions(
    date_str: str = Path(..., regex=r'^\d{4}-\d{2}-\d{2}$', alias="date"),
    model: str = Path(...),
    min_prob: float = Query(0.94, ge=0.0, le=0.95),  # Default is 0.94
    max_prob: float = Query(1.0, ge=0.0, le=1.0),   # Default is 1.0
    category: Optional[str] = Query(None),
    district: Optional[str] = Query(None)
):
    """
    Get predictions for a specific date from finalpredictions table.
    
    This endpoint no longer computes predictions on the fly but fetches from precalculated data.
    The model parameter is kept for backward compatibility.
    """
    try:
        logger.info(f"Getting predictions for date: {date_str}, model: {model}")

        # Convert string date to date object for PostgreSQL
        try:
            year, month, day = map(int, date_str.split('-'))
            date_obj = date(year, month, day)  # Create Python date object
        except Exception as e:
            logger.error(f"Error parsing date: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid date format: {date}")

        # Build the query based on parameters
        query = """
        SELECT 
            latitude, longitude, prediction_date::text, valid_time::text, fire_prob,
            fire_category, gapa_napa, district, pr_name, province
        FROM finalpredictions 
        WHERE prediction_date = :date
        """
        
        params = {
            "date": date_obj
        }
        
        # Add category filter if specified
        if category:
            query += " AND fire_category = :category"
            params["category"] = category.lower()
            
        # Add district filter if specified
        if district:
            query += " AND district ILIKE :district"
            params["district"] = f"%{district}%"
            
        # Order by fire probability (highest first)
        query += " ORDER BY fire_prob DESC"
        
        # Execute query
        async with async_session() as session:
            result = await session.execute(text(query), params)
            rows = result.fetchall()
            
        if not rows:
            return []
        
        # Convert to response objects
        return [
            PredictionResponse(
                latitude=row[0],
                longitude=row[1],
                prediction_date=row[2],
                fire_prob=row[4],
                fire_category=row[5],
                gapa_napa=row[6],
                district=row[7],
                pr_name=row[8],
                province=row[9]
            )
            for row in rows
            if (0.94 < row.fire_prob <= 0.95) or (0.99 < row.fire_prob <= 1.0)
        ]
    except Exception as e:
        logger.error(f"Error fetching predictions: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch predictions: {str(e)}")

@app.get("/prediction-stats", response_model=PredictionStats)
async def get_prediction_stats(date: Optional[str] = Query(None, regex=r'^\d{4}-\d{2}-\d{2}$')):
    """Get statistics about fire predictions"""
    try:
        # Base query for stats
        if date:
            # Stats for specific date
            where_clause = "WHERE prediction_date = :date"
            params = {"date": date}
        else:
            # Stats for all dates
            where_clause = ""
            params = {}
        
        # Get counts by category
        category_query = f"""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN fire_category = 'high' THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN fire_category = 'medium' THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN fire_category = 'low' THEN 1 ELSE 0 END) as low_risk,
            SUM(CASE WHEN fire_category = 'minimal' THEN 1 ELSE 0 END) as minimal_risk,
            MIN(prediction_date)::text as min_date,
            MAX(prediction_date)::text as max_date
        FROM finalpredictions
        {where_clause}
        """
        
        # Get top risk areas
        top_areas_query = f"""
        SELECT 
            district,
            COUNT(*) as prediction_count,
            AVG(fire_prob)::numeric(10,4) as avg_prob,
            MAX(fire_prob)::numeric(10,4) as max_prob
        FROM finalpredictions
        {where_clause}
        GROUP BY district
        ORDER BY avg_prob DESC
        LIMIT 10
        """
        
        async with async_session() as session:
            # Get category counts
            stats_result = await session.execute(text(category_query), params)
            stats_result = stats_result.fetchone()
            
            # Get top risk areas
            areas_result = await session.execute(text(top_areas_query), params)
            areas_result = areas_result.fetchall()
            
        if not stats_result:
            raise HTTPException(status_code=404, detail="No prediction data found")
            
        # Format top areas
        top_risk_areas = [
            {
                "district": area[0] or "Unknown",
                "prediction_count": area[1],
                "avg_probability": float(area[2]),
                "max_probability": float(area[3])
            }
            for area in areas_result
        ]
        
        # Return stats
        return {
            "total_predictions": stats_result[0],
            "high_risk_count": stats_result[1],
            "medium_risk_count": stats_result[2],
            "low_risk_count": stats_result[3],
            "minimal_risk_count": stats_result[4],
            "date_range": {
                "start": stats_result[5],
                "end": stats_result[6]
            },
            "top_risk_areas": top_risk_areas
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting prediction stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get prediction stats: {str(e)}")

@app.get("/available-dates", response_model=List[str])
async def get_available_prediction_dates():
    """Get all available dates for predictions"""
    try:
        query = "SELECT DISTINCT prediction_date::text FROM finalpredictions ORDER BY prediction_date DESC"
        
        async with async_session() as session:
            result = await session.execute(text(query))
            dates = [row[0] for row in result]
            
        return dates
    except Exception as e:
        logger.error(f"Error getting available dates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get available dates: {str(e)}")

# -------------------- Alert Routes --------------------

@app.get("/public/alerts", response_model=List[Alert])
async def get_public_alerts():
    """Get all active public alerts"""
    try:
        query = """
        SELECT 
            id, title, message, level, location, latitude, longitude, created_at, is_active
        FROM alerts 
        WHERE is_active = TRUE
        ORDER BY created_at DESC
        """
        
        async with async_session() as session:
            result = await session.execute(text(query))
            alerts = [
                Alert(
                    id=row[0],
                    title=row[1],
                    message=row[2],
                    level=row[3],
                    location=row[4],
                    latitude=row[5],
                    longitude=row[6],
                    created_at=row[7],
                    is_active=row[8]
                )
                for row in result
            ]
            
        return alerts
    except Exception as e:
        logger.error(f"Error getting public alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")

@app.post("/admin/generate-prediction-alerts", status_code=201)
async def generate_prediction_alerts(date: str = Query(..., regex=r'^\d{4}-\d{2}-\d{2}$')):
    """Generate alerts based on predictions from the finalpredictions table"""
    try:
        # Get high and medium risk predictions
        query = """
        SELECT 
            latitude, longitude, prediction_date, fire_prob,
            fire_category, gapa_napa, district
        FROM finalpredictions 
        WHERE prediction_date = :date
        AND (
            (fire_prob > 0.99 AND fire_category = 'high') OR 
            (fire_prob > 0.94 AND fire_category = 'medium')
        )
        ORDER BY fire_prob DESC
        """
        
        async with async_session() as session:
            result = await session.execute(text(query), {"date": date})
            high_risk_predictions = result.fetchall()
            
        if not high_risk_predictions:
            return {"message": "No high risk areas found for alert generation"}
        
        # Create alerts for high-risk areas
        alerts_created = 0
        
        async with async_session() as session:
            async with session.begin():
                for row in high_risk_predictions:
                    latitude, longitude, prediction_date, fire_prob, fire_category, gapa_napa, district = row
                    location = gapa_napa or district or "Unknown location"
                    
                    # Check if similar alert already exists
                    check_query = """
                    SELECT id FROM alerts 
                    WHERE latitude = :latitude 
                    AND longitude = :longitude
                    AND created_at >= NOW() - INTERVAL '24 hours'
                    """
                    
                    existing = await session.execute(
                        text(check_query), 
                        {"latitude": latitude, "longitude": longitude}
                    )
                    existing = existing.fetchone()
                    
                    if existing:
                        continue  # Skip if alert already exists
                    
                    # Create alert
                    district_name = district or "the area"
                    level = "danger" if fire_category == "high" else "warning"
                    
                    insert_query = """
                    INSERT INTO alerts (
                        title, message, level, location, latitude, longitude, created_at, is_active
                    ) VALUES (
                        :title, :message, :level, :location, :latitude, :longitude, NOW(), TRUE
                    )
                    """
                    
                    title = f"{'High' if level == 'danger' else 'Medium'} Fire Risk Alert - {district_name}"
                    message = f"{'Extreme' if level == 'danger' else 'Elevated'} fire danger detected near {location} with probability of {fire_prob:.2f}. {'Immediate action recommended.' if level == 'danger' else 'Monitoring advised.'}"
                    
                    await session.execute(
                        text(insert_query),
                        {
                            "title": title,
                            "message": message,
                            "level": level,
                            "location": location,
                            "latitude": latitude,
                            "longitude": longitude
                        }
                    )
                    
                    alerts_created += 1
        
        return {"message": f"Generated {alerts_created} alerts from fire predictions"}
    except Exception as e:
        logger.error(f"Error generating alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate alerts: {str(e)}")

# -------------------- CSV Upload for Predictions --------------------

@app.post("/admin/upload-predictions", status_code=201)
async def upload_predictions_csv(
    file: UploadFile = File(...),
    overwrite: bool = Form(False)
):
    try:
        # First, check if the finalpredictions table exists
        if not await table_exists("finalpredictions"):
            # Table doesn't exist, create it
            predictions_table = """
            CREATE TABLE IF NOT EXISTS finalpredictions (
                id SERIAL PRIMARY KEY,
                latitude FLOAT NOT NULL,
                longitude FLOAT NOT NULL,
                prediction_date DATE NOT NULL,
                valid_time TIMESTAMP,
                fire_prob FLOAT NOT NULL,
                prediction_class INTEGER,
                fire_category VARCHAR(50),
                gapa_napa VARCHAR(255),
                district VARCHAR(255),
                pr_name VARCHAR(255),
                province FLOAT
            )
            """
            async with async_session() as session, session.begin():
                await session.execute(text(predictions_table))
                logger.info("Created finalpredictions table")
        
        # Check if file is CSV
        if not file.filename.endswith('.csv'):
            raise HTTPException(status_code=400, detail="File must be a CSV")
        
        # Read CSV content
        contents = await file.read()
        
        # Parse CSV
        try:
            df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error parsing CSV: {str(e)}")
        
        # Validate required columns
        required_columns = ['latitude', 'longitude', 'prediction_date', 'valid_time', 'fire_prob', 'prediction_class']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            raise HTTPException(
                status_code=400,
                detail=f"CSV is missing required columns: {', '.join(missing_columns)}"
            )
        
        # Ensure prediction_date is in correct format (YYYY-MM-DD)
        try:
            df['prediction_date'] = pd.to_datetime(df['prediction_date']).dt.strftime('%Y-%m-%d')
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error processing prediction_date: {str(e)}")
        
        # Ensure valid_time is in correct datetime format
        try:
            df['valid_time'] = pd.to_datetime(df['valid_time'])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error processing valid_time: {str(e)}")
        
        # Add fire_category if not present
        if 'fire_category' not in df.columns:
            df['fire_category'] = df['fire_prob'].apply(lambda p: 
                'high' if p > 0.99 else 
                'medium' if p > 0.94 else 
                'low' if p > 0.8 else 
                'minimal'
            )
        
        # Standardize column names to lowercase
        column_mapping = {}
        for col in df.columns:
            if col in ["GaPa_NaPa", "DISTRICT", "PR_NAME", "PROVINCE"]:
                lowercase_col = col.lower()
                column_mapping[col] = lowercase_col
        
        # Apply column renaming if needed
        if column_mapping:
            df = df.rename(columns=column_mapping)
        
        # Add optional columns if not present
        optional_columns = ['gapa_napa', 'district', 'pr_name', 'province']
        for col in optional_columns:
            if col not in df.columns:
                df[col] = None
        
        # Check if any predictions already exist
        unique_dates = df['prediction_date'].unique()
        
        # Convert string dates to actual date objects for PostgreSQL
        date_objects = []
        for date_str in unique_dates:
            # Create Python date objects from strings
            if re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
                year, month, day = map(int, date_str.split('-'))
                date_obj = date(year, month, day)
                date_objects.append(date_obj)
            else:
                logger.warning(f"Invalid date format: {date_str}")
        
        # Open a new session for checking existing dates
        async with async_session() as session:
            # Check for existing dates
            existing_dates = []
            if len(date_objects) == 1:
                check_query = text("SELECT DISTINCT prediction_date::text FROM finalpredictions WHERE prediction_date = :date")
                result = await session.execute(check_query, {"date": date_objects[0]})
                existing_dates = [row[0] for row in result]
            elif len(date_objects) > 1:
                check_query = text("SELECT DISTINCT prediction_date::text FROM finalpredictions WHERE prediction_date = ANY(:dates)")
                result = await session.execute(check_query, {"dates": date_objects})
                existing_dates = [row[0] for row in result]
            
            if existing_dates and not overwrite:
                return {
                    "message": f"Some dates already have predictions. Use overwrite=true to replace them.",
                    "existing_dates": existing_dates,
                    "status": "conflict"
                }
        
        # Open a new session for deleting existing records if needed
        if existing_dates and overwrite:
            async with async_session() as session, session.begin():
                if len(existing_dates) == 1:
                    delete_query = text("DELETE FROM finalpredictions WHERE prediction_date = :date")
                    await session.execute(delete_query, {"date": date_objects[0]})
                else:
                    delete_query = text("DELETE FROM finalpredictions WHERE prediction_date = ANY(:dates)")
                    await session.execute(delete_query, {"dates": date_objects})
                logger.info(f"Deleted existing predictions for dates: {existing_dates}")
        
        # Open a new session for the column check
        async with async_session() as session:
            # Get the actual column names from the database table
            inspect_query = text("""
            SELECT column_name 
            FROM information_schema.columns
            WHERE table_name='finalpredictions'
            ORDER BY ordinal_position
            """)
            
            result = await session.execute(inspect_query)
            db_columns = [row[0] for row in result]
            
        logger.info(f"Database columns: {db_columns}")
        logger.info(f"DataFrame columns: {df.columns.tolist()}")
        
        # Keep only columns that exist in the database table
        columns_to_keep = [col for col in df.columns if col.lower() in [c.lower() for c in db_columns]]
        df_clean = df[columns_to_keep]
        
        # Insert rows in batches with a separate transaction
        inserted_count = 0
        batch_size = 100  # Process records in batches of 100
        total_rows = len(df_clean)
        
        for i in range(0, total_rows, batch_size):
            batch_df = df_clean.iloc[i:i+batch_size]
            
            # Open a new session for each batch insertion
            async with async_session() as session, session.begin():
                for _, row in batch_df.iterrows():
                    # Convert date and timestamp strings to objects
                    date_str = row['prediction_date']
                    if isinstance(date_str, str) and re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
                        year, month, day = map(int, date_str.split('-'))
                        row['prediction_date'] = date(year, month, day)
                    
                    # Create INSERT statement
                    cols = ', '.join(columns_to_keep)
                    placeholders = ', '.join(f':{col}' for col in columns_to_keep)
                    insert_query = f"""
                    INSERT INTO finalpredictions ({cols})
                    VALUES ({placeholders})
                    """
                    
                    # Create parameters dict for this row
                    params = {col: row[col] for col in columns_to_keep}
                    
                    try:
                        # Execute insert with proper parameter typing
                        await session.execute(text(insert_query), params)
                        inserted_count += 1
                    except Exception as row_error:
                        logger.error(f"Error inserting row {inserted_count}: {str(row_error)}")
                        # Continue with next row
                        continue
                
                logger.info(f"Inserted batch {i//batch_size + 1}, rows {i+1} to {min(i+batch_size, total_rows)}")
        
        # Return summary
        return {
            "message": "Predictions successfully uploaded",
            "rows_processed": inserted_count,
            "dates_processed": [d.strftime('%Y-%m-%d') for d in date_objects],
            "status": "success"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing CSV upload: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to process CSV: {str(e)}")

# -------------------- User Management Routes --------------------

@app.get("/admin/users", response_model=List[User])
async def get_users():
    """Get all users (admin only)"""
    try:
        query = """
        SELECT id, email, full_name, role, created_at
        FROM users
        ORDER BY id
        """
        
        async with async_session() as session:
            result = await session.execute(text(query))
            users = [
                User(
                    id=row[0],
                    email=row[1],
                    full_name=row[2],
                    role=row[3],
                    created_at=row[4]
                )
                for row in result
            ]
            
        return users
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get users: {str(e)}")

@app.post("/admin/users", response_model=User)
async def create_user(user: UserCreate):
    """Create a new user (admin only)"""
    # Check if user already exists
    existing_user = await get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Insert new user
    query = text("""
    INSERT INTO users (email, full_name, hashed_password, role, created_at)
    VALUES (:email, :full_name, :hashed_password, :role, NOW())
    RETURNING id, email, full_name, role, created_at
    """)
    
    try:
        async with async_session() as session, session.begin():
            result = await session.execute(
                query, 
                {
                    "email": user.email,
                    "full_name": user.full_name,
                    "hashed_password": hashed_password,
                    "role": user.role
                }
            )
            new_user = result.fetchone()
            
            if not new_user:
                raise HTTPException(status_code=500, detail="Failed to create user")
                
            return User(
                id=new_user[0],
                email=new_user[1],
                full_name=new_user[2],
                role=new_user[3],
                created_at=new_user[4]
            )
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@app.put("/admin/users/{user_id}", response_model=User)
async def update_user(user_id: int, user_update: UserCreate):
    """Update a user (admin only)"""
    try:
        # Check if user exists
        check_query = text("""
        SELECT id FROM users WHERE id = :user_id
        """)
        
        async with async_session() as session:
            result = await session.execute(check_query, {"user_id": user_id})
            user_exists = result.fetchone()
            
            if not user_exists:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Check if email is being changed and if it's already taken
            if user_update.email:
                check_email_query = text("""
                SELECT id FROM users WHERE email = :email AND id != :user_id
                """)
                
                result = await session.execute(
                    check_email_query, 
                    {"email": user_update.email, "user_id": user_id}
                )
                existing_email = result.fetchone()
                
                if existing_email:
                    raise HTTPException(status_code=400, detail="Email already in use")
            
            # Update user
            update_query = text("""
            UPDATE users
            SET email = :email,
                full_name = :full_name,
                role = :role
                """ + 
                (", hashed_password = :hashed_password" if user_update.password else "") + """
            WHERE id = :user_id
            RETURNING id, email, full_name, role, created_at
            """)
            
            params = {
                "user_id": user_id,
                "email": user_update.email,
                "full_name": user_update.full_name,
                "role": user_update.role
            }
            
            if user_update.password:
                params["hashed_password"] = get_password_hash(user_update.password)
            
            async with session.begin():
                result = await session.execute(update_query, params)
                updated_user = result.fetchone()
                
            if not updated_user:
                raise HTTPException(status_code=500, detail="Failed to update user")
                
            return User(
                id=updated_user[0],
                email=updated_user[1],
                full_name=updated_user[2],
                role=updated_user[3],
                created_at=updated_user[4]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update user: {str(e)}")

@app.delete("/admin/users/{user_id}", status_code=204)
async def delete_user(user_id: int):
    """Delete a user (admin only)"""
    try:
        # Check if user exists
        check_query = text("""
        SELECT id FROM users WHERE id = :user_id
        """)
        
        async with async_session() as session:
            result = await session.execute(check_query, {"user_id": user_id})
            user_exists = result.fetchone()
            
            if not user_exists:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Delete user
            delete_query = text("""
            DELETE FROM users WHERE id = :user_id
            """)
            
            async with session.begin():
                await session.execute(delete_query, {"user_id": user_id})
                
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")

# -------------------- Alert Management Routes --------------------

@app.get("/admin/alerts", response_model=List[Alert])
async def get_alerts():
    """Get all alerts (admin only)"""
    try:
        query = """
        SELECT 
            id, title, message, level, location, latitude, longitude, created_at, is_active
        FROM alerts
        ORDER BY created_at DESC
        """
        
        async with async_session() as session:
            result = await session.execute(text(query))
            alerts = [
                Alert(
                    id=row[0],
                    title=row[1],
                    message=row[2],
                    level=row[3],
                    location=row[4],
                    latitude=row[5],
                    longitude=row[6],
                    created_at=row[7],
                    is_active=row[8]
                )
                for row in result
            ]
            
        return alerts
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")

@app.post("/admin/alerts", response_model=Alert)
async def create_alert(alert: AlertCreate):
    """Create a new alert (admin only)"""
    try:
        # Insert new alert
        query = text("""
        INSERT INTO alerts (title, message, level, location, latitude, longitude, created_at, is_active)
        VALUES (:title, :message, :level, :location, :latitude, :longitude, NOW(), TRUE)
        RETURNING id, title, message, level, location, latitude, longitude, created_at, is_active
        """)
        
        async with async_session() as session, session.begin():
            result = await session.execute(
                query, 
                {
                    "title": alert.title,
                    "message": alert.message,
                    "level": alert.level,
                    "location": alert.location,
                    "latitude": alert.latitude,
                    "longitude": alert.longitude
                }
            )
            new_alert = result.fetchone()
            
        if not new_alert:
            raise HTTPException(status_code=500, detail="Failed to create alert")
            
        return Alert(
            id=new_alert[0],
            title=new_alert[1],
            message=new_alert[2],
            level=new_alert[3],
            location=new_alert[4],
            latitude=new_alert[5],
            longitude=new_alert[6],
            created_at=new_alert[7],
            is_active=new_alert[8]
        )
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create alert: {str(e)}")

@app.put("/admin/alerts/{alert_id}", response_model=Alert)
async def update_alert(alert_id: int, alert_update: AlertCreate):
    """Update an alert (admin only)"""
    try:
        # Check if alert exists
        check_query = text("""
        SELECT id FROM alerts WHERE id = :alert_id
        """)
        
        async with async_session() as session:
            result = await session.execute(check_query, {"alert_id": alert_id})
            alert_exists = result.fetchone()
            
            if not alert_exists:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            # Update alert
            update_query = text("""
            UPDATE alerts
            SET title = :title,
                message = :message,
                level = :level,
                location = :location,
                latitude = :latitude,
                longitude = :longitude
            WHERE id = :alert_id
            RETURNING id, title, message, level, location, latitude, longitude, created_at, is_active
            """)
            
            async with session.begin():
                result = await session.execute(
                    update_query, 
                    {
                        "alert_id": alert_id,
                        "title": alert_update.title,
                        "message": alert_update.message,
                        "level": alert_update.level,
                        "location": alert_update.location,
                        "latitude": alert_update.latitude,
                        "longitude": alert_update.longitude
                    }
                )
                updated_alert = result.fetchone()
                
            if not updated_alert:
                raise HTTPException(status_code=500, detail="Failed to update alert")
                
            return Alert(
                id=updated_alert[0],
                title=updated_alert[1],
                message=updated_alert[2],
                level=updated_alert[3],
                location=updated_alert[4],
                latitude=updated_alert[5],
                longitude=updated_alert[6],
                created_at=updated_alert[7],
                is_active=updated_alert[8]
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update alert: {str(e)}")

@app.delete("/admin/alerts/{alert_id}", status_code=204)
async def delete_alert(alert_id: int):
    """Delete an alert (admin only)"""
    try:
        # Check if alert exists
        check_query = text("""
        SELECT id FROM alerts WHERE id = :alert_id
        """)
        
        async with async_session() as session:
            result = await session.execute(check_query, {"alert_id": alert_id})
            alert_exists = result.fetchone()
            
            if not alert_exists:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            # Delete alert
            delete_query = text("""
            DELETE FROM alerts WHERE id = :alert_id
            """)
            
            async with session.begin():
                await session.execute(delete_query, {"alert_id": alert_id})
                
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete alert: {str(e)}")

# -------------------- Database Initialization --------------------

async def init_db():
    """Create tables if they don't exist"""
    users_table = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        hashed_password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT NOW()
    )
    """
    
    alerts_table = """
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        level VARCHAR(50) NOT NULL,
        location VARCHAR(255),
        latitude FLOAT,
        longitude FLOAT,
        created_at TIMESTAMP DEFAULT NOW(),
        is_active BOOLEAN DEFAULT TRUE
    )
    """

    predictions_table = """
    CREATE TABLE IF NOT EXISTS finalpredictions (
        id SERIAL PRIMARY KEY,
        latitude FLOAT NOT NULL,
        longitude FLOAT NOT NULL,
        prediction_date DATE NOT NULL,
        valid_time TIMESTAMP,
        fire_prob FLOAT NOT NULL,
        prediction_class INTEGER,
        fire_category VARCHAR(50),
        gapa_napa VARCHAR(255),
        district VARCHAR(255),
        pr_name VARCHAR(255),
        province FLOAT
    )
    """
    
    # Add indices for commonly queried columns
    create_indices = """
    CREATE INDEX IF NOT EXISTS idx_finalpred_date ON finalpredictions (prediction_date);
    CREATE INDEX IF NOT EXISTS idx_finalpred_category ON finalpredictions (fire_category);
    CREATE INDEX IF NOT EXISTS idx_finalpred_district ON finalpredictions (district);
    CREATE INDEX IF NOT EXISTS idx_finalpred_prob ON finalpredictions (fire_prob);
    """
    
    try:
        async with async_session() as session, session.begin():
            await session.execute(text(users_table))
            await session.execute(text(alerts_table))
            await session.execute(text(predictions_table))
            await session.execute(text(create_indices))
            logger.info("Database tables initialized")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")


async def table_exists(table_name: str) -> bool:
    """Check if a table exists in the database"""
    query = text("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = :table_name
    )
    """)
    
    async with async_session() as session:
        result = await session.execute(query, {"table_name": table_name})
        return result.scalar()
    

async def init_admin_user():
    """Create admin user if it doesn't exist"""
    try:
        # Check if admin user exists
        admin_query = text("""
        SELECT id FROM users WHERE email = :email
        """)
        
        async with async_session() as session:
            result = await session.execute(admin_query, {"email": "admin@example.com"})
            admin_exists = result.fetchone()
            
            if not admin_exists:
                # Create admin user
                create_admin_query = text("""
                INSERT INTO users (email, full_name, hashed_password, role, created_at)
                VALUES (:email, :full_name, :hashed_password, 'admin', NOW())
                """)
                
                async with session.begin():
                    await session.execute(
                        create_admin_query, 
                        {
                            "email": "admin@example.com",
                            "full_name": "Admin User",
                            "hashed_password": get_password_hash("admin123")
                        }
                    )
                    logger.info("Admin user created")
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")

@app.on_event("startup")
async def startup_event():
    """Initialize database and admin user on startup"""
    await init_db()
    await init_admin_user()

# -------------------- Run Server --------------------

if __name__ == "__main__":
    uvicorn.run("prediction_api:app", host="0.0.0.0", port=8000, reload=True)