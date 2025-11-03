import os
import uuid
import json
import logging
import asyncio
import re
import smtplib 
import bcrypt 
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Dict, Union 
from email.mime.text import MIMEText 
from email.utils import formataddr 

import aiosmtplib 

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status, Body, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field 
from bson import ObjectId

# --- CRITICAL NEW IMPORT for OAuth Session ---
from starlette.middleware.sessions import SessionMiddleware
# ---------------------------------------------

# --- Gemini ---
import google.generativeai as genai

# --- MongoDB ---
import motor.motor_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

# --- Passwords / JWT ---
from jose import JWTError, jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# --- Redis (async) ---
import redis.asyncio as aioredis

# --- OAuth (Google + GitHub) ---
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

# -------------------------
# Logging & Environment
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
load_dotenv()

# -------------------------
# Config
# -------------------------
# Use a default URL, and ensure we strip the slash to match standard browser requests
VERCEL_FRONTEND_ORIGIN_RAW = os.getenv("VERCEL_FRONTEND_ORIGIN", "https://echo-frontend-5r3l.vercel.app/")
VERCEL_FRONTEND_ORIGIN = VERCEL_FRONTEND_ORIGIN_RAW.rstrip('/')
API_BASE_URL = os.getenv("API_BASE_URL", "https://echo-backend-1-ubeb.onrender.com")

# -------------------------
# Email Configuration (SendGrid SMTP)
# -------------------------
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Sender Details
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "support@yourcompany.com")
SENDER_NAME = os.getenv("SENDER_NAME", "echo-mid") 

# -------------------------
# MongoDB
# -------------------------
MONGO_URI = os.getenv("MONGODB_URI")

# -------------------------
# Redis Setup (optional)
# -------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# -------------------------
# Password Hashing & JWT
# -------------------------
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-for-jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "14"))

# --- START: UPDATED PASSWORD FUNCTIONS ---
def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    if not hashed_password:
        return False
        
    try:
        plain_password_bytes = plain_password.encode('utf-8')[:72]
        hashed_password_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)
    except ValueError as e:
        logging.error(f"Password verification failed: {e}")
        return False
        
def get_password_hash(password: str) -> str:
    password_bytes = password.encode('utf-8')[:72]
    
    hashed_password_bytes = bcrypt.hashpw(
        password_bytes, 
        bcrypt.gensalt() # Generates a new random salt
    )
    return hashed_password_bytes.decode('utf-8')
# --- END: UPDATED PASSWORD FUNCTIONS ---

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# MongoDB User Lookup Function
async def get_user_by_email_mongo(email: str) -> Optional[Dict]:
    """Retrieves a user document from MongoDB by email."""
    col = getattr(app.state, "users_collection", None)
    if col is None:
        return None
    return await col.find_one({"email": email})

# Dependency to get current user from JWT (Authorization: Bearer or cookie)
auth_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme),
    request: Request = None,
) -> Optional[Dict]: # Returns MongoDB document (Dict)
    token = None
    if credentials:
        token = credentials.credentials
    else:
        # Check cookie first
        token = request.cookies.get("access_token") if request else None
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            return None
        # Use the MongoDB user lookup function
        return await get_user_by_email_mongo(email)
    except JWTError:
        return None

async def get_current_agent_or_admin(current_user: Optional[Dict] = Depends(get_current_user)):
    """Dependency to check if the current user has agent or admin privileges."""
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    user_role = current_user.get("role", "user")
    if user_role not in ["agent", "admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
        
    return current_user # Return the user object if authorized

async def get_current_admin(current_user: Optional[Dict] = Depends(get_current_user)):
    """Dependency to check if the current user has admin privileges."""
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    user_role = current_user.get("role", "user")
    if user_role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
        
    return current_user # Return the user object if authorized


# --- CRITICAL KEYWORDS ---
CRITICAL_KEYWORDS = [
    "urgent", "critical", "immediate action", "ASAP", "emergency", "crisis",
    "angry", "furious", "outraged", "unacceptable", "fuming", "highly dissatisfied", 
    "stuck", "stranded", "trapped", "cannot proceed", "must resolve now",
    "cancel immediately", "close account now", "stop service now",
    "threaten", "lawsuit", "legal action", "contacting my lawyer", 
    "media", "public complaint", "escalate to management", 
    "unresponsive", "lied to",
    "not working", "completely down", "system failure", "major outage", "global outage", 
    "broken", "crashed", "frozen", "inoperable", "unresponsive", "unusable", "malfunction",
    "error 500", "fatal error", "critical bug", "server error", "API failure", "network down",
    "can't connect", "no access", "locked out", "system exploited",
    "data loss", "deleted", "corrupted", "lost all my progress", "data breach", "data leak",
    "denial of service", "DDoS", "virus", "malware",
    "fraud", "scam", "money lost", "loss of funds", "stolen", "dispute charge", 
    "unauthorized payment", "unauthorized transaction", "immediate refund", 
    "overcharged", "excessive fee", "billing error", "incorrect statement",
    "identity theft", "account compromise", "frozen account", "locked funds",
    "transfer failed", "payment bounced", "repossession", "foreclosure",
    "close credit card", "cancel payment", "tax issue", "IRS",
    "missed flight", "stuck at airport", "cannot board", "denied boarding", "no record of reservation",
    "visa rejected", "customs issue", "immigration problem", "denied entry", "deportation",
    "illness", "injury", "medical emergency", "police involved",
    "stranded overseas", "unsafe location", "security threat",
    "delayed more than 5 hours", "cancelled last minute", "hotel won't honor",
    "lost passport", "stolen tickets", "no transport", "emergency evacuation", 
    "overbooked", "no room available",
]

# NEW: Restricted list for immediate ticket generation
HIGH_SEVERITY_KEYWORDS = [
    # Security / Financial
    "fraud", "scam", "stolen", "identity theft", "data breach", "account compromise",
    "unauthorized payment", "unauthorized transaction", "immediate refund", "money lost",
    "legal action", "lawsuit", "contacting my lawyer",
    
    # System Down / Emergency
    "completely down", "major outage", "global outage", "fatal error", "critical bug",
    "emergency", "crisis", "stranded", "trapped", "must resolve now", 
    "reset password", "change login",
    
    # Extreme Urgency / Danger
    "urgent", "critical", "ASAP", "immediate action",
]


def check_critical_issue(user_query: str, sentiment: str) -> bool:
    """Checks for critical keywords, using the restricted HIGH_SEVERITY_KEYWORDS for ticket generation."""
    text = user_query.lower()
    
    # TIER 1: High-Security/Immediate Action (returns True regardless of sentiment)
    HIGH_SECURITY_KWS = ["reset password", "change login", "account blocked", "fraud", "security issue"]
    if any(kw in text for kw in HIGH_SECURITY_KWS):
        return True

    # TIER 2: HIGH SEVERITY check for immediate ticket creation
    for kw in HIGH_SEVERITY_KEYWORDS:
        if kw in text:
            # Enforce a sentiment check only for a slightly more controlled trigger
            if sentiment == "NEGATIVE" or kw in ["fraud", "data breach", "outage", "emergency"]:
                return True
                
    return False

# -------------------------
# Gemini Setup (safe wrapper)
# -------------------------
gemini_api_key = os.getenv("GEMINI_API_KEY")
if gemini_api_key:
    try:
        genai.configure(api_key=gemini_api_key)
        logging.info("✅ Gemini configured")
    except Exception as e:
        logging.warning(f"Gemini configure failed: {e}")
else:
    logging.warning("GEMINI_API_KEY missing — Gemini features disabled.")

GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-2.5-flash")

async def _call_gemini(prompt_text: str, *, temperature: float = 0.7, max_output_tokens: int = 512) -> str:
    """
    Compatible wrapper. Runs sync SDK calls in an executor to avoid blocking.
    """
    if not gemini_api_key:
        return "Sorry, AI is temporarily unavailable."
    try:
        loop = asyncio.get_running_loop()
        # Modern SDK
        if hasattr(genai, "GenerativeModel"):
            def sync_call():
                model = genai.GenerativeModel(GEMINI_MODEL_NAME)
                try:
                    return model.generate_content(prompt_text)
                except TypeError:
                    return model.generate_content(prompt_text, generation_config={"temperature": temperature, "max_output_tokens": max_output_tokens})
            resp = await loop.run_in_executor(None, sync_call)
            if hasattr(resp, "text") and resp.text:
                return resp.text
            if hasattr(resp, "candidates") and resp.candidates:
                cand = resp.candidates[0]
                content = getattr(cand, "content", None)
                if content and getattr(content, "parts", None):
                    p0 = content.parts[0]
                    return getattr(p0, "text", str(p0)) or ""
            if hasattr(resp, "generations"):
                try:
                    return resp.generations[0].text
                except Exception:
                    return str(resp.generations[0])
            return ""
        # Older helper
        if hasattr(genai, "generate_text"):
            def sync_generate():
                # NOTE: Changed from genai.generate_generate_text to genai.generate_text
                return genai.generate_text(model=GEMINI_MODEL_NAME, prompt=prompt_text) 
            resp = await loop.run_in_executor(None, sync_generate)
            if hasattr(resp, "text") and resp.text:
                return resp.text
            if hasattr(resp, "generations"):
                return resp.generations[0].text
            return ""
        return "Sorry, AI is temporarily unavailable."
    except Exception as e:
        logging.error(f"Gemini error: {e}")
        return "Sorry, I am unable to process your request now."

# -------------------------
# Transformers Pipelines (REMOVED: Now using heuristics/Gemini only)
# -------------------------
sentiment_analyzer = None # CRITICAL: This bypasses memory-heavy model loading
zero_shot_classifier = None # CRITICAL: This bypasses memory-heavy model loading
INTENT_LABELS = ["general", "technical", "finance", "travel"]
ZERO_SHOT_THRESHOLD = float(os.getenv("ZERO_SHOT_THRESHOLD", "0.55"))

logging.info("ℹ️ Local ML models disabled to meet 512MiB memory limit. Using heuristics and Gemini API.")

# -------------------------
# Domain Knowledge Base (In-Memory Fallback)
# -------------------------
try:
    with open("domain_questions.json", "r") as f:
        domain_knowledge_bases = json.load(f)
    logging.info("✅ Loaded domain-specific KB from domain_questions.json")
except FileNotFoundError:
    domain_knowledge_bases = {
        "general": {"refund status": "Refunds take 5–7 business days."},
        "technical": {"internet not working": "Restart router/modem and check service status."},
        "finance": {"billing inquiry": "Provide account number or check last bill online."},
        "travel": {"change plan": "Use the portal or speak with a sales rep."}
    }
    logging.info("ℹ domain_questions.json not found — using default KB.")

# -------------------------
# Helper Functions (MONGO-based)
# -------------------------

def analyze_sentiment(text: str) -> str:
    # Since sentiment_analyzer is None, this will always use the keyword fallback.
    t = text.lower()
    if any(w in t for w in ["not working", "frustrated", "annoyed", "unhappy", "bad", "terrible", "issue", "problem"]):
        return "NEGATIVE"
    if any(w in t for w in ["thank you", "resolved", "great", "happy", "good", "excellent", "thanks"]):
        return "POSITIVE"
    return "NEUTRAL"

def _keyword_intent(text: str) -> Tuple[str, float, str]:
    t = text.lower()
    if any(k in t for k in ["wifi", "router", "internet", "bug", "error", "crash", "install", "api", "server"]):
        return ("technical", 0.7, "rules")
    if any(k in t for k in ["refund", "invoice", "billing", "charge", "payment", "tax", "bank", "balance", "account"]):
        return ("finance", 0.8, "rules")
    if any(k in t for k in ["flight", "hotel", "booking", "reservation", "itinerary", "visa", "tour"]):
        return ("travel", 0.7, "rules")
    return ("general", 0.6, "rules")

async def classify_intent(text: str) -> Tuple[str, float, str]:
    """
    Returns (predicted_domain, confidence[0..1], source['gemini'|'rules'])
    The zero-shot path is intentionally removed to save memory.
    """
    # 1) Zero-shot (local) - SKIP

    # 2) Gemini (Remote AI)
    if gemini_api_key:
        prompt = (
            "You are an intent classifier. Classify the user query into EXACTLY ONE of these domains: "
            "[general, technical, finance, travel].\n"
            f"Query: {text!r}\n"
            "Return only the domain name."
        )
        out = await _call_gemini(prompt)
        domain = (out or "").strip().lower()
        if "technical" in domain or "tech" in domain:
            return ("technical", 0.6, "gemini")
        if "finance" in domain:
            return ("finance", 0.6, "gemini")
        if "travel" in domain:
            return ("travel", 0.6, "gemini")
        return ("general", 0.6, "gemini")

    # 3) Rules (Fallback)
    return _keyword_intent(text)

async def get_history_answer(user_query: str) -> Optional[str]:
    """
    Checks the chat_history collection globally for an exact match of a user's query.
    """
    col = getattr(app.state, "chat_history_collection", None)
    if col is None:
        logging.debug("chat_history_collection not configured; skipping global history check.")
        return None

    normalized_query = user_query.strip().lower()

    try:
        user_message_doc = await col.find_one({
            "role": "user",
            "content": {"$regex": f"^{re.escape(normalized_query)}$", "$options": "i"}
        }, sort=[("timestamp", -1)])

        if not user_message_doc:
            return None
        
        found_session_id = user_message_doc["session_id"]
        found_timestamp = user_message_doc["timestamp"]

        bot_response_doc = await col.find_one({
            "session_id": found_session_id,
            "role": "bot",
            "timestamp": {"$gt": found_timestamp}
        }, sort=[("timestamp", 1)])

        if bot_response_doc:
            source = bot_response_doc.get("meta", {}).get("source", "unknown")
            if source not in ["KB", "Gemini", "Fallback"]:
                return None
                
            logging.info(f"✅ Found GLOBAL history match (Source: {source}) for query: {user_query[:30]}...")
            return bot_response_doc["content"]

    except Exception as e:
        logging.error(f"Error checking global chat history for reuse: {e}")
        return None

    return None

# --- MODIFIED: Save chat history with user_email and added logging ---
async def save_chat_history_message(session_id: str, role: str, content: str, user_email: str, meta: Optional[Dict] = None):
    """
    Stores a single message (user or bot) into app.state.chat_history_collection
    """
    col = getattr(app.state, "chat_history_collection", None)
    
    if col is None:
        logging.error("CRITICAL ERROR: chat_history_collection is NOT configured or failed to initialize.")
        return
        
    if not user_email or user_email == "anonymous@example.com":
        logging.warning(f"Skipping history save: Invalid or anonymous user email ({user_email}).")
        return
        
    doc = {
        "session_id": session_id,
        "role": role,
        "content": content,
        "user_email": user_email,  # <-- NEW: Storing user email for retrieval
        "meta": meta or {},
        "timestamp": datetime.utcnow(),
    }
    try:
        result = await col.insert_one(doc)
        if result.inserted_id:
            logging.info(f"✅ History saved for {user_email}. Role: {role}. ID: {result.inserted_id}")
        else:
             logging.error(f"❌ History save failed for {user_email}: Insert acknowledged but no ID returned.")
    except Exception as e:
        logging.error(f"FATAL DB WRITE ERROR: Failed to save chat history message for {user_email}: {e}")
# ---------------------------------------------------------------------


async def get_kb_answer(user_query: str, domain: str) -> Optional[str]:
    """
    Asynchronously looks up a direct answer in the MongoDB faq_knowledge_base collection.
    """
    col = getattr(app.state, "faq_kb_collection", None)
    text = user_query.lower()

    if col is not None:
        try:
            cursor = col.find({"domain": domain})
            async for doc in cursor:
                if isinstance(doc.get("keywords"), list):
                    for keyword in doc["keywords"]:
                        if keyword.lower() in text:
                            return doc.get("answer", f"Found an answer for '{keyword}' but content is missing.")
                
                if doc.get("subject") and doc["subject"].lower() in text:
                    return doc.get("answer")
                    
        except Exception as e:
            logging.error(f"MongoDB KB lookup failed: {e}")
    else:
        logging.debug("MongoDB FAQ KB collection is not configured.")

    # Fallback to the original in-memory KB
    for key, val in domain_knowledge_bases.get(domain, {}).items():
        if key in user_query.lower():
            return val
            
    return None

async def get_case_resolution_context(customer_id: str, domain: str, user_query: str) -> str:
    """
    Queries MongoDB for recent, resolved cases matching the domain, then uses
    Gemini to summarize the most relevant one(s) for prompt injection (RAG).
    """
    col = getattr(app.state, "cases_collection", None)
    if col is None:
        return "No historical case context available."
    
    # 1. Retrieve the top 5 recently resolved cases for this customer/domain
    cursor = col.find({
        "customer_id": customer_id,
        "domain": domain,
        "status": {"$in": ["resolved", "closed"]}
    }).sort("last_updated", -1).limit(5)
    
    resolved_cases = await cursor.to_list(length=5)
    
    if not resolved_cases:
        return "No relevant resolved case history for this query."
        
    # 2. Format cases for summarization
    case_texts = []
    for i, case in enumerate(resolved_cases):
        resolution_text = case.get("summary") or case.get("initial_query") + " ... " + \
            " ".join([m['content'] for m in case.get("conversation_history", [])[-2:]])
        
        case_texts.append(f"Case {i+1} (Subject: {case.get('subject', 'N/A')}): {resolution_text[:200]}")

    # 3. Use Gemini to find and summarize the most relevant context
    context_prompt = (
        f"Analyze the Customer's current query: {user_query!r}. "
        f"Below are past, resolved support cases for this customer in the {domain} domain. "
        "Select the 1-2 most relevant cases that might help resolve the current query. "
        "Summarize the relevant cases and their resolution steps concisely. "
        "If none are relevant, reply only with 'No relevant history found.'.\n\n"
        f"Available Cases:\n" + "\n".join(case_texts)
    )

    summary = await _call_gemini(context_prompt, temperature=0.2, max_output_tokens=300)
    
    # Return a clean context block
    if summary and summary.lower().strip() != 'no relevant history found.':
        return f"Past Resolved Cases for Customer:\n{summary}\n"
    
    return "No relevant resolved case history for this query."


async def generate_bot_response(user_query: str, conversation_history: List["ChatMessage"], domain: str, customer_id: str) -> str:
    """
    Generates a bot response using Gemini, injecting context from past resolved cases AND 
    retrieved customer profile for personalization.
    """
    if not gemini_api_key:
        return "Sorry, AI is temporarily unavailable."

    # --- 1. RETRIEVE CUSTOMER PROFILE DATA ---
    cust_col = getattr(app.state, "customers_collection", None)
    profile_data = {}
    
    if cust_col is not None and customer_id:
        try:
            profile_doc = await cust_col.find_one({"_id": customer_id})
            if profile_doc:
                sentiment_history = profile_doc.get("sentiment_history", [])
                
                # Simple analysis: Count negative vs. others in the last 10 interactions
                recent_sentiments = sentiment_history[-10:]
                negative_count = recent_sentiments.count("NEGATIVE")
                
                if negative_count >= 3:
                    profile_data['tone_suggestion'] = "Be highly empathetic, apologetic, and prioritize speed."
                else:
                    profile_data['tone_suggestion'] = "Be efficient, professional, and friendly."
                    
                profile_data['preferences'] = profile_doc.get("preference_settings", "Standard.")
                
        except Exception as e:
            logging.warning(f"Failed to retrieve customer profile for personalization: {e}")

    # --- 2. RETRIEVE RAG CONTEXT (Past Case Resolutions) ---
    case_context = await get_case_resolution_context(customer_id, domain, user_query)
    
    context_messages = [f"{msg.role}: {msg.content}" for msg in conversation_history[-10:]]
    
    # --- 3. CONSTRUCT PERSONALIZED PROMPT ---
    
    personalization_context = (
        f"You are a helpful {domain} support agent. Always adhere to the CUSTOMER PERSONALIZATION RULES. "
        f"CUSTOMER PERSONALIZATION RULES:\n"
        f"- Target Tone: {profile_data.get('tone_suggestion', 'Be efficient and helpful.')}\n"
        f"- Communication Preferences: {profile_data.get('preferences', 'Standard.')}\n\n"
    )

    prompt = (
        f"You are a helpful {domain} support agent. Always adhere to the CUSTOMER PERSONALIZATION RULES. "
        f"{personalization_context}"
        "Answer the customer's query concisely and professionally.\n\n"
        
        f"Historical Context for Resolution:\n{case_context}\n\n"
        
        f"Current Conversation Context (last 10 messages):\n" + "\n".join(context_messages) + "\n\n"
        f"Customer: {user_query}\n"
        "Support Agent:"
    )
    answer = await _call_gemini(prompt)
    return answer

def should_escalate(bot_response: str) -> bool:
    """
    Decide if the bot's response signals that it cannot answer,
    and escalation to human is required.
    """
    if not bot_response:
        return False
    text = bot_response.lower()
    signals = [
        "i cannot", "cannot answer", "unable to", "can't help with",
        "sorry, i cannot", "need human", "escalate"
    ]
    return any(sig in text for sig in signals)

async def create_mongo_ticket(
    customer_id: str, 
    subject: str, 
    description: str,
    domain: str,
    failure_reason: str
) -> Optional[str]:
    """Creates a ticket in MongoDB and returns the new ticket ID (ObjectId str)."""
    col = getattr(app.state, "tickets_collection", None)
    if col is None:
        logging.error("MongoDB tickets_collection not configured.")
        return None
        
    try:
        # Append the specific failure reason to the description
        full_description = f"{description}\n\nFAILURE REASON: {failure_reason}"
        
        new_ticket = {
            "customer_id": customer_id,
            "subject": subject[:255],
            "description": full_description,
            "domain": domain,
            "status": "open",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            # Initialize conversation history with the initial message
            "conversation_history": [{"role": "user", "content": description, "timestamp": datetime.utcnow()}]
        }
        result = await col.insert_one(new_ticket)
        ticket_id = str(result.inserted_id)
        logging.info(f"🚨 MongoDB Ticket created in {domain}: {ticket_id}")
        return ticket_id
    except Exception as e:
        logging.error(f"MongoDB Ticket Creation Failed: {e}")
        return None

async def insert_faq_document(domain: str, keywords: list, answer: str):
    """
    Inserts a new FAQ document into the MongoDB faq_knowledge_base collection.
    Returns the inserted document's ID.
    """
    col = getattr(app.state, "faq_kb_collection", None)
    if col is None:
        raise HTTPException(status_code=500, detail="FAQ KB collection not configured")
    doc = {
        "domain": domain,
        "keywords": keywords,
        "answer": answer,
        "status": "manual",
        "created_at": datetime.utcnow(),
    }
    try:
        result = await col.insert_one(doc)
        return str(result.inserted_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to insert FAQ document: {e}")

async def add_message_to_ticket(ticket_id: str, message: str, role: str) -> bool:
    """Appends a new message to the conversation history of a ticket."""
    col = getattr(app.state, "tickets_collection", None)
    if col is None:
        logging.error("MongoDB tickets_collection not configured.")
        return False
        
    try:
        message_doc = {
            "role": role,
            "content": message,
            "timestamp": datetime.utcnow(),
        }
        
        # Determine the query ID (ObjectId or string ID)
        is_valid_object_id = len(ticket_id) == 24 and ObjectId.is_valid(ticket_id)
        query_id = ObjectId(ticket_id) if is_valid_object_id else ticket_id
        
        update_result = await col.update_one(
            {"$or": [{"_id": query_id}, {"id": ticket_id}]},
            {
                "$push": {"conversation_history": message_doc},
                "$set": {"updated_at": datetime.utcnow()},
            },
        )
        
        if update_result.matched_count == 0:
            logging.warning(f"Ticket not found for message update: {ticket_id}")
            return False

        logging.info(f"Message added to ticket: {ticket_id}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to add message to ticket: {e}")
        return False

# Helper function to get ticket details (used for email context)
async def get_ticket(ticket_id: str) -> Optional[Dict]:
    col = getattr(app.state, "tickets_collection", None)
    if col is None:
        return None
    try:
        is_valid_object_id = len(ticket_id) == 24 and ObjectId.is_valid(ticket_id)
        query_id = ObjectId(ticket_id) if is_valid_object_id else ticket_id
        ticket_doc = await col.find_one({"$or": [{"_id": query_id}, {"id": ticket_id}]})
        
        if ticket_doc:
            ticket_doc["_id"] = str(ticket_doc["_id"])
        return ticket_doc
    except Exception as e:
        logging.error(f"Error fetching ticket for email context: {e}")
        return None
    
# Helper function to get customer email
async def get_customer_email(customer_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Retrieves customer email and name from the users collection."""
    col = getattr(app.state, "users_collection", None)
    if col is None:
        return None, None
    
    try:
        is_valid_object_id = len(customer_id) == 24 and ObjectId.is_valid(customer_id)
        query_id = ObjectId(customer_id) if is_valid_object_id else customer_id

        # Search by _id (if valid ObjectId) or by the 'id' field (if string UUID)
        customer_doc = await col.find_one({"$or": [{"_id": query_id}, {"id": customer_id}]}, {"email": 1, "name": 1})
        
        # FIX: Fallback lookup by email address (for tickets linked by email)
        if not customer_doc and "@" in customer_id:
            customer_doc = await col.find_one({"email": customer_id}, {"email": 1, "name": 1})

        if customer_doc:
            return customer_doc.get("email"), customer_doc.get("name")
        return None, None
        
    except Exception as e:
        logging.error(f"Error fetching customer email for ID {customer_id}: {e}")
        return None, None

# Async Email Sending Function (REVERTED TO SENDGRID SMTP)
async def send_email_notification(
    to_email: str, 
    subject: str, 
    body: str, 
    customer_name: Optional[str] = None, 
    is_resolution: bool = False 
):
    """
    Sends an email using aiosmtplib via the SendGrid SMTP Relay.
    FIXED: Uses correct encryption parameters for port 587 (solving the start_tls/use_tls conflict).
    """
    if not all([SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD]):
        logging.warning("SMTP configuration missing. Cannot send email notification.")
        return False

    try:
        # 1. Construct the MIME message
        final_body = (
            f"Dear {customer_name or 'Customer'},\n\n"
            f"Subject: {subject}\n\n"
            f"{body}\n\n"
            f"Regards,\n{SENDER_NAME} Team"
        )
        
        msg = MIMEText(final_body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = formataddr((SENDER_NAME, SENDER_EMAIL))
        msg['To'] = to_email

        # 2. Send the message using aiosmtplib
        await aiosmtplib.send(
            msg,
            hostname=SMTP_SERVER,      
            port=SMTP_PORT,            
            username=SMTP_USERNAME,    
            password=SMTP_PASSWORD,    
            # CRITICAL FIX: Only use start_tls for port 587 connections (SendGrid standard)
            start_tls=(SMTP_PORT == 587),
            use_tls=(SMTP_PORT == 465)  # Use use_tls ONLY if port 465 is configured
        )
        
        logging.info(f"✅ SUCCESS: Email sent via SendGrid SMTP to {to_email}.")
        return True
    
    except aiosmtplib.SMTPException as e:
        logging.error(f"SMTP Error (SendGrid) sending email to {to_email}: {e}")
        return False
    except Exception as e:
        logging.error(f"General Email Error sending to {to_email}: {e}")
        return False
        
# -------------------------
# FastAPI App
# -------------------------
app = FastAPI(
    title="Customer Support Chatbot Backend (Hybrid: Mongo + Redis + Gemini + OAuth + Intent)",
    version="1.5.0",
)

# --- CRITICAL FIX: Add Session Middleware for Authlib/OAuth ---
# The SECRET_KEY is necessary to securely sign the session cookie.
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY) 
# -------------------------------------------------------------


# --- FIX: ROBUST CORS CONFIGURATION ---
ALLOWED_ORIGINS = [
    VERCEL_FRONTEND_ORIGIN,
    VERCEL_FRONTEND_ORIGIN + "/", # Added to explicitly handle trailing slash (though stripping above is better)
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# -------------------------------------


# -------------------------
# Pydantic Models 
# -------------------------
class UserBase(BaseModel):
    name: str
    email: EmailStr

class UserRegister(UserBase):
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None

class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: str

class HistoryMessage(BaseModel):
    # CRITICAL: If frontend expects '_id' as ID, it must be aliased here
    id: str = Field(..., alias="_id")
    session_id: str
    role: str
    content: str
    user_email: Optional[EmailStr] = None # <-- ADDED: For history retrieval consistency
    timestamp: datetime # Use datetime for precise time display
    meta: Optional[Dict] = {}
    
    class Config:
        # Allows conversion from MongoDB's '_id' to the 'id' field
        json_encoders = {ObjectId: str}
        populate_by_name = True

class CustomerProfile(BaseModel):
    customer_id: str
    previous_interactions: List[str] = []
    purchase_history: List[str] = []
    preference_settings: dict = {}
    sentiment_history: List[str] = []
    active_case_id: Optional[str] = None

class ChatRequest(BaseModel):
    user_query: str
    session_id: str
    customer_profile: CustomerProfile
    conversation_history: List[ChatMessage] = []
    domain: str 

class ChatResponse(BaseModel):
    bot_response: str
    case_status: str = "open"
    case_id: Optional[str] = None
    faq_suggestion: Optional[str] = None
    sentiment_detected: Optional[str] = None
    predicted_domain: Optional[str] = None
    intent_confidence: Optional[float] = None
    intent_source: Optional[str] = None

class TicketCreate(BaseModel):
    customer_id: str
    subject: str
    description: Optional[str] = None

# MODIFIED: Model to include the final resolution message
class TicketResolution(BaseModel):
    status: str = Field(..., description="Must be 'resolved' to include resolution_message.")
    resolution_message: Optional[str] = Field(None, description="The final message sent to the customer explaining the resolution.")

class HistorySummaryResponse(BaseModel):
    session_id: str
    summary: str

class NewFaqEntry(BaseModel):
    domain: str
    keywords: List[str]
    answer: str

# NEW: Model for Admin User List
class AdminUserResponse(BaseModel):
    id: str = Field(..., alias="_id")
    name: str
    email: EmailStr
    role: str
    created_at: datetime
    # Allows Pydantic to handle ObjectId conversion
    class Config:
        json_encoders = {ObjectId: str}
        allow_population_by_field_name = True

# NEW: Model for Role Update
class RoleUpdate(BaseModel):
    new_role: str
    
# -------------------------
# Startup / Shutdown 
# -------------------------
@app.on_event("startup")
async def on_startup():
    # Redis
    try:
        app.state.redis = await aioredis.from_url(
            f"redis://{REDIS_HOST}:{REDIS_PORT}", decode_responses=True
        )
        logging.info("✅ Redis connected and stored in app.state.redis.")
    except Exception as e:
        app.state.redis = None
        logging.warning(f"Redis connection failed: {e}")

    # MongoDB + ping
    try:
        if MONGO_URI:
            app.state.mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
            default_db = app.state.mongo_client.get_default_database()
            app.state.chatbot_db = default_db if default_db is not None else app.state.mongo_client["chatbot"]
            
            # --- Mongo Collections for migrated data ---
            app.state.users_collection = app.state.chatbot_db["users"] 
            app.state.tickets_collection = app.state.chatbot_db["tickets"] 
            
            # --- Existing Mongo Collections ---
            app.state.orders_collection = app.state.chatbot_db["orders"]
            app.state.cases_collection = app.state.chatbot_db["cases"]
            app.state.customers_collection = app.state.chatbot_db["customers"]
            app.state.chat_history_collection = app.state.chatbot_db["chat_history"]
            app.state.faq_kb_collection = app.state.chatbot_db["faq_knowledge_base"]
            
            # Create indexes for efficiency
            await app.state.users_collection.create_index("email", unique=True)
            await app.state.tickets_collection.create_index("customer_id")
            # --- NEW INDEX for history retrieval by email ---
            await app.state.chat_history_collection.create_index("user_email")

            await app.state.mongo_client.admin.command("ping")
            logging.info("✅ MongoDB connected, ping succeeded, and collections/indexes set up.")
        else:
            raise RuntimeError("MONGODB_URI not set")
    except Exception as e:
        logging.error(f"MongoDB startup failed: {e}")
        app.state.mongo_client = None
        app.state.chatbot_db = None
        app.state.users_collection = None
        app.state.tickets_collection = None
        app.state.orders_collection = None
        app.state.cases_collection = None
        app.state.customers_collection = None
        app.state.chat_history_collection = None
        app.state.faq_kb_collection = None 

@app.on_event("shutdown")
async def on_shutdown():
    if getattr(app.state, "redis", None) is not None:
        await app.state.redis.close()
    if getattr(app.state, "mongo_client", None) is not None:
        app.state.mongo_client.close()

# -------------------------
# DB helpers 
# -------------------------
async def get_redis():
    return getattr(app.state, "redis", None)

# -------------------------
# WebSocket auth helper (FIXED for 403)
# -------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # This handler uses the manual authentication check from get_ws_user
    await websocket.accept()
    user = await get_ws_user(websocket)
    
    if not user:
        # get_ws_user already closed the connection with 1008 policy violation
        return

    user_email = user.get('email', 'unknown')
    logging.info(f"WebSocket connected for user: {user_email}")
    
    try:
        while True:
            # Simple echo server for connection testing
            data = await websocket.receive_text()
            logging.info(f"WS received from {user_email}: {data}")
            await websocket.send_text(f"Message received: {data}")
            
    except WebSocketDisconnect:
        logging.info(f"WebSocket disconnected for user: {user_email}")
    except Exception as e:
        logging.error(f"WebSocket runtime error for {user_email}: {e}")
    finally:
        pass 

async def get_ws_user(websocket: WebSocket) -> Optional[Dict]: 
    token = None
    # Check 1: Query Params (used by AuthContext on connection attempt)
    if "token" in websocket.query_params:
        token = websocket.query_params["token"]
    # Check 2: Cookies (less reliable in some cross-origin WS setups, but standard)
    elif "access_token" in websocket.cookies:
        token = websocket.cookies.get("access_token")
        
    if not token:
        # Rejecting unauthorized connection early
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION) 
        return None
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return None
            
        # Use MongoDB lookup
        user = await get_user_by_email_mongo(email)
        
        # Check if user exists
        if not user:
             await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
             return None
             
        return user
        
    except JWTError as e:
        logging.warning(f"WS JWT Error: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
    except Exception as e:
        logging.error(f"WS Unexpected Error: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None


# -------------------------
# OAuth Setup 
# -------------------------
starlette_config = Config(environ={
    "GOOGLE_CLIENT_ID": os.getenv("GOOGLE_CLIENT_ID", ""),
    "GOOGLE_CLIENT_SECRET": os.getenv("GOOGLE_CLIENT_SECRET", ""),
    "GITHUB_CLIENT_ID": os.getenv("GITHUB_CLIENT_ID", ""),
    "GITHUB_CLIENT_SECRET": os.getenv("GITHUB_CLIENT_SECRET", ""),
})
oauth = OAuth(starlette_config)

oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID", ""),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET", ""),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)

def _frontend_redirect_with_token_cookie(token: str) -> RedirectResponse:
    # Use the hardcoded/fixed VERCEL_FRONTEND_ORIGIN here
    url = f"{VERCEL_FRONTEND_ORIGIN}/auth/callback" 
    resp = RedirectResponse(url=url, status_code=302)
    resp.set_cookie(
        "access_token", token,
        httponly=True, secure=True, samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES*60
    )
    return resp

@app.get("/auth/{provider}/login")
async def oauth_login(provider: str, request: Request):
    if provider not in ("google", "github"):
        raise HTTPException(400, "Unsupported provider")
    redirect_uri = f"{API_BASE_URL}/auth/{provider}/callback"
    client = oauth.create_client(provider)
    # This line now relies on SessionMiddleware being active
    return await client.authorize_redirect(request, redirect_uri)

@app.get("/auth/{provider}/callback")
async def oauth_callback(provider: str, request: Request): 
    if provider not in ("google", "github"):
        raise HTTPException(400, "Unsupported provider")
    client = oauth.create_client(provider)
    
    # Authlib step 1: Authorize access token and get response (which might or might not contain id_token)
    token = await client.authorize_access_token(request) 
    
    email = None
    name = None

    if provider == "google":
        # --- CRITICAL FIX START: Handle missing id_token ---
        # Instead of failing on token['id_token'], we use the access token 
        # to fetch user information directly from Google's userinfo endpoint.
        try:
            # Use the access token to get the user's detailed profile
            user_info_resp = await client.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
            user_info_resp.raise_for_status() 
            user_info = user_info_resp.json()
        except Exception as e:
            logging.error(f"Google user info fetch failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve Google user profile.")
            
        email = user_info.get("email")
        name = user_info.get("name") or (email.split("@")[0] if email else "")
        # --- CRITICAL FIX END ---
        
    else: # GitHub logic remains the same
        resp = await client.get("user", token=token)
        data = resp.json()
        name = data.get("name") or data.get("login")
        emails_resp = await client.get("user/emails", token=token)
        emails = emails_resp.json()
        primary = next((e["email"] for e in emails if e.get("primary")), None)
        email = primary or (emails[0]["email"] if emails else None)

    if not email:
        raise HTTPException(400, "Email not available from provider")

    users_col = getattr(app.state, "users_collection", None)
    if users_col is None:
        raise HTTPException(status_code=500, detail="User database not available")

    existing = await get_user_by_email_mongo(email)
    if not existing:
        # Determine role for new OAuth users
        assigned_role = assign_role_by_name(name) if name else "user"
        
        new_user = {
            # Relying on MongoDB to generate _id
            "name": name or email.split("@")[0],
            "email": email,
            "hashed_password": None, 
            "role": assigned_role, 
            "created_at": datetime.utcnow(),
        }
        await users_col.insert_one(new_user)
    
    # create token
    access_token = create_access_token({"sub": email})
    return _frontend_redirect_with_token_cookie(access_token)

SENSITIVE_FINANCE_PATTERN = re.compile(
    r"\b(balance|account number|account no|ssn|social security|pin|password|full account|how much money|how much is my balance|statement)\b",
    re.I,
)

# -------------------------
# Role Assignment Logic (Refined)
# -------------------------
def assign_role_by_name(name: str) -> str:
    """Assigns role based on name pattern: 'admin' if name contains 'admin', 'agent' if name contains 'agent', otherwise 'user'."""
    name_lower = name.lower().strip()
    
    # Standardize and simplify the string for matching
    clean_name = re.sub(r'[^a-z0-9]', '', name_lower)

    # 1. Admin Role Check
    if 'admin' in clean_name:
        if re.search(r'admin\d*|admin[a-z]*', clean_name) or clean_name == "admin":
             return "admin"
    
    # 2. Agent Role Check
    if 'agent' in clean_name:
        if re.search(r'agent\d*|agent', clean_name):
            return "agent"

    # Default role
    return "user"

# --- NEW HELPER FUNCTION for Consistent ID Retrieval ---
def get_user_mongo_id(user_doc: Dict) -> str:
    """Safely retrieves the primary MongoDB ObjectId string from a user document."""
    # Prioritize the MongoDB _id
    if user_doc.get("_id"):
        return str(user_doc["_id"])
    # Fallback to the deprecated 'id' field if _id is missing
    return user_doc.get("id", "no-id")
# -----------------------------------------------------

# -------------------------
# Auth Endpoints (Email/Password) 
# -------------------------
@app.post("/register")
async def register(user: UserRegister): 
    users_col = getattr(app.state, "users_collection", None)
    if users_col is None:
        raise HTTPException(status_code=500, detail="User database not available")

    exists = await get_user_by_email_mongo(user.email)
    if exists:
        raise HTTPException(status_code=409, detail="Email already registered")
        
    # --- CRITICAL FIX: SAVING ROLE ---
    assigned_role = assign_role_by_name(user.name)
    
    new_user = {
        # CRITICAL FIX: Relying on MongoDB to generate _id, removing redundant UUID
        "name": user.name,
        "email": user.email,
        "hashed_password": get_password_hash(user.password),
        "role": assigned_role, 
        "created_at": datetime.utcnow(),
    }
    
    result = await users_col.insert_one(new_user)
    
    # Use the MongoDB ObjectId string as customer_id
    customer_id = str(result.inserted_id) 
    
    logging.info(f"New user registered: {user.email} with role: {assigned_role}. Stored ID: {customer_id}")
    
    r = await get_redis()
    if r:
        try:
            # Store the native MongoDB ID string for consistency
            await r.set(f"user:{user.email}", customer_id) 
        except Exception as e:
            logging.warning(f"Redis set failed (non-blocking): {e}")
            
    # Return the MongoDB ObjectId string as customer_id
    return {"ok": True, "customer_id": customer_id, "role": assigned_role} 

@app.post("/login")
async def login(request: LoginRequest):
    user = await get_user_by_email_mongo(request.email)
    
    # This call now uses the new verify_password with 72-byte truncation
    if not user or not user.get("hashed_password") or not verify_password(request.password, user.get("hashed_password")):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Retrieve stored role and customer ID
    user_role = user.get("role", "user") 
    customer_id = get_user_mongo_id(user) # Use the new helper function
    
    accesstoken = create_access_token(data={"sub": user["email"]}) 
    refreshtoken = create_refresh_token(data={"sub": user["email"]}) 
    
    logging.info(f"User logged in: {user['email']} with role: {user_role}")
    
    return {
        "access_token": accesstoken,
        "token_type": "bearer",
        "refresh_token": refreshtoken,
        "id": customer_id, 
        "role": user_role,
        "name": user.get("name"),
        "email": user.get("email")
    }

@app.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str = Body(..., embed=True)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(401, "Invalid refresh token")
        new_access = create_access_token({"sub": email})
        new_refresh = create_refresh_token({"sub": email})
        return {"access_token": new_access, "token_type": "bearer", "refresh_token": new_refresh}
    except JWTError:
        raise HTTPException(401, "Invalid refresh token")

@app.get("/me")
async def me(current_user: Optional[Dict] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        
    customer_id = get_user_mongo_id(current_user) # Use the new helper function
    return {
        "id": customer_id, 
        "name": current_user["name"], 
        "email": current_user["email"],
        "role": current_user.get("role", "user") 
    }

# -------------------------
# NEW: History Endpoints (FIX for 404 and consistency)
# -------------------------
@app.get("/history", response_model=List[HistoryMessage])
async def get_user_chat_history(
    current_user: Dict = Depends(get_current_user), 
):
    """
    Retrieves the persistent chat history for the currently authenticated user
    by querying the chat_history collection using multiple keys (email and old ID).
    """
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    chat_history_col = getattr(app.state, "chat_history_collection", None)
    user_email = current_user.get("email")
    customer_id = get_user_mongo_id(current_user) # Get the MongoDB ObjectId string

    
    if chat_history_col is None:
        logging.error("chat_history_collection not configured; cannot fetch history.")
        return [] 
        
    if not user_email or customer_id == "no-id":
        logging.warning("Authenticated user has incomplete ID/email for history query.")
        return []
    
    try:
        # --- CRITICAL FIX: Use $or to query based on EITHER email (new) or customer_id (old/fallback) ---
        query_filter = {
            "$or": [
                {"user_email": user_email}, # Matches documents saved with the new logic
                {"session_id": customer_id}  # Matches old documents saved with the ObjectId string
            ]
        }

        cursor = chat_history_col.find(query_filter).sort("timestamp", 1) 
        
        history_list = await cursor.to_list(length=1000)
            
        logging.info(f"Retrieved {len(history_list)} history messages for user {user_email}.")
        
        # Pydantic will serialize the list using the HistoryMessage model
        return history_list

    except Exception as e:
        logging.error(f"Error fetching user chat history for {user_email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve chat history.")

@app.delete("/history/delete_all", status_code=status.HTTP_200_OK)
async def delete_user_chat_history(
    current_user: Dict = Depends(get_current_user),
):
    """Deletes all chat history associated with the currently authenticated user."""
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    chat_history_col = getattr(app.state, "chat_history_collection", None)
    user_email = current_user.get("email")
    
    if chat_history_col is None:
        raise HTTPException(status_code=500, detail="Database not configured.")
    
    if not user_email:
        raise HTTPException(status_code=400, detail="User email not available for deletion filter.")

    try:
        # Use delete_many() with the permanent identifier (email)
        delete_result = await chat_history_col.delete_many(
            {"user_email": user_email}
        )
        
        logging.info(f"🗑️ Deleted {delete_result.deleted_count} chat history messages for user: {user_email}.")
        
        return {
            "message": "All chat history deleted successfully.",
            "deleted_count": delete_result.deleted_count,
            "user_email": user_email,
        }

    except Exception as e:
        logging.error(f"Error deleting chat history for {user_email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete chat history.")
# ---------------------------------------------------------------------

# -------------------------
# Dynamic Customer Profile Endpoint
# -------------------------
@app.get("/customer/{customer_id}/profile")
async def get_customer_profile(
    customer_id: str,
    current_user: Dict = Depends(get_current_agent_or_admin) # Secure this endpoint
):
    """Retrieves dynamic profile information for a given customer ID."""
    users_col = getattr(app.state, "users_collection", None)
    if users_col is None:
        raise HTTPException(status_code=500, detail="User database not available.")

    # 1. Prepare query criteria
    query_criteria = []
    
    # Check if the provided ID is a valid MongoDB ObjectId
    is_valid_object_id = len(customer_id) == 24 and ObjectId.is_valid(customer_id)
    
    if is_valid_object_id:
        query_criteria.append({"_id": ObjectId(customer_id)})
    
    # Always check against the stored string 'id' (for older UUIDs)
    query_criteria.append({"id": customer_id})
    
    # NEW: Check if the ID string itself is an email address (to handle frontend passing email)
    if "@" in customer_id:
        query_criteria.append({"email": customer_id})

    # If no criteria were generated, something is wrong
    if not query_criteria:
        raise HTTPException(status_code=400, detail="Invalid identifier format provided.")

    try:
        # 2. Search the collection
        customer_doc = await users_col.find_one(
            {"$or": query_criteria},
            {"email": 1, "name": 1, "created_at": 1, "role": 1}
        )

        if not customer_doc:
            raise HTTPException(status_code=404, detail=f"Customer record not found for ID/Email: {customer_id}")

        # 3. Return profile
        customer_profile = {
            "name": customer_doc.get("name", "N/A"),
            "email": customer_doc.get("email", "N/A"),
            "tier": "VIP" if customer_doc.get("role") in ["admin", "agent"] else "Standard",
            "join_date": customer_doc.get("created_at", datetime.min).isoformat(),
            "last_sentiment": "Neutral 😐", 
        }

        return customer_profile

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error fetching customer profile: {e}")
        raise HTTPException(status_code=500, detail="Internal server error fetching profile.")

# -------------------------
# Ticket Endpoints 
# -------------------------

@app.get("/tickets")
async def get_all_open_tickets(
    current_user: Dict = Depends(get_current_agent_or_admin)
):
    """Retrieves all non-resolved, non-closed tickets for the agent dashboard."""
    col = getattr(app.state, "tickets_collection", None)
    if col is None:
        raise HTTPException(status_code=500, detail="Ticket database not available.")
    
    try:
        # Fetch tickets that are 'open' or 'escalated', sorted by oldest first
        cursor = col.find({"status": {"$in": ["open", "escalated", "pending"]}}).sort("created_at", 1)
        
        # Convert documents to a list, ensuring ObjectId is converted to str
        tickets_list = []
        async for doc in cursor:
            doc['_id'] = str(doc['_id'])
            tickets_list.append(doc)

        return tickets_list
        
    except Exception as e:
        logging.error(f"Error fetching open tickets: {e}")
        raise HTTPException(status_code=500, detail="Error fetching tickets.")


# REMOVED: /tickets/{ticket_id}/message endpoint is intentionally removed.

@app.post("/tickets", status_code=status.HTTP_201_CREATED)
async def create_ticket_endpoint(data: TicketCreate):
    ticket_id = await create_mongo_ticket(
        customer_id=data.customer_id,
        subject=data.subject,
        description=data.description or "Initial ticket creation.",
        domain="manual",
        failure_reason="Manual creation via API endpoint."
    )
    if not ticket_id:
        raise HTTPException(status_code=500, detail="Failed to create ticket in MongoDB.")
    return {"ticket_id": ticket_id, "status": "open"}

@app.get("/tickets/{ticket_id}")
async def get_ticket_endpoint(ticket_id: str):
    """Fetches a single ticket, ensuring ObjectId conversion and 404 handling."""
    ticket_doc = await get_ticket(ticket_id)
    if not ticket_doc:
        raise HTTPException(status_code=404, detail="Ticket not found.")
    return ticket_doc


@app.put("/tickets/{ticket_id}/status")
async def update_ticket_status(
    ticket_id: str, 
    update: TicketResolution, # <-- Now requires resolution_message for 'resolved'
    current_user: Dict = Depends(get_current_agent_or_admin) 
):
    col = getattr(app.state, "tickets_collection", None)
    if col is None:
        raise HTTPException(status_code=500, detail="Ticket database not available.")
    
    new_status = update.status.lower()
    
    # Validation: Resolution message is required when resolving a ticket
    if new_status == "resolved" and not update.resolution_message:
        raise HTTPException(status_code=400, detail="Resolution message is required when marking a ticket as 'resolved'.")
        
    try:
        is_valid_object_id = len(ticket_id) == 24 and ObjectId.is_valid(ticket_id)
        # CRITICAL FIX APPLIED HERE: Define query_id correctly
        query_id = ObjectId(ticket_id) if is_valid_object_id else ticket_id

        # Prepare update operation
        update_op = {"$set": {"status": new_status, "updated_at": datetime.utcnow()}}

        # If resolved, add the agent's final message to the conversation history
        if new_status == "resolved" and update.resolution_message:
            # 1. Record the agent's message in the ticket history
            agent_message = {
                "role": "agent",
                "content": update.resolution_message,
                "timestamp": datetime.utcnow(),
                "meta": {"type": "Resolution"}
            }
            update_op["$push"] = {"conversation_history": agent_message}
            
        update_result = await col.update_one(
            {"$or": [{"_id": query_id}, {"id": ticket_id}]},
            update_op
        )

        if update_result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Ticket not found.")

        # 2. Trigger Email Notification (Only if resolved)
        if new_status == "resolved":
            ticket_doc = await get_ticket(ticket_id)
            if ticket_doc:
                customer_email, customer_name = await get_customer_email(ticket_doc.get("customer_id"))
                
                if customer_email:
                    subject = f"Ticket Resolved: {ticket_doc.get('subject', f'Ticket ID: {ticket_id}')}"
                    
                    # Dispatch Email (non-blocking)
                    asyncio.create_task(
                        send_email_notification(
                            to_email=customer_email, 
                            subject=subject, 
                            body=update.resolution_message, # The single message the agent sent
                            customer_name=customer_name,
                            is_resolution=True 
                        )
                    )
                else:
                    logging.warning(f"Could not send resolution email: Customer email not found for ticket {ticket_id}.")
            
        return {"ticket_id": ticket_id, "new_status": new_status, "ok": True}
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating ticket status: {e}")
        raise HTTPException(status_code=500, detail="Error updating ticket status.")

# ----------------------------------------
# ADMIN DASHBOARD ENDPOINTS
# ----------------------------------------

@app.get("/admin/metrics")
async def get_admin_metrics(current_user: Dict = Depends(get_current_admin)):
    """Calculates key metrics for the Admin Dashboard overview."""
    
    users_col = getattr(app.state, "users_collection", None)
    tickets_col = getattr(app.state, "tickets_collection", None)
    
    if not users_col or not tickets_col:
        raise HTTPException(status_code=500, detail="Database collections not available.")

    now = datetime.utcnow()
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 1. User/Agent Counts
    total_users = await users_col.count_documents({})
    total_agents = await users_col.count_documents({"role": "agent"})
    
    # 2. Ticket Counts
    total_open = await tickets_col.count_documents({"status": {"$in": ["open", "escalated", "pending"]}})
    
    # 3. SLA Breaches (Tickets older than 48 hours and still open/pending)
    overdue_limit = now - timedelta(days=2)
    sla_breach = await tickets_col.count_documents({
        "status": {"$in": ["open", "escalated", "pending"]},
        "created_at": {"$lt": overdue_limit}
    })
    
    # 4. Resolved Today
    resolved_today = await tickets_col.count_documents({
        "status": "resolved",
        "updated_at": {"$gte": start_of_day}
    })

    # MOCK DATA for performance metrics (requires dedicated pipelines in a full system)
    agent_performance_mock = [
        {"name": "Alice", "resolved": 25, "rating": 4.9, "status": "Online"},
        {"name": "Bob", "resolved": 19, "rating": 4.7, "status": "Away"},
        {"name": "Charlie", "resolved": 31, "rating": 4.6, "status": "Online"},
    ]

    return {
        "totalUsers": total_users,
        "totalAgents": total_agents,
        "avgSatisfaction": 4.7, # Mock
        "resolvedToday": resolved_today,
        "pendingTickets": total_open,
        "slaBreach": sla_breach,
        "ticketsInProcess": total_open, # Mock: using total_open for simple metric
        "agentPerformance": agent_performance_mock
    }


@app.get("/admin/users", response_model=List[AdminUserResponse])
async def get_all_users(current_user: Dict = Depends(get_current_admin)):
    """Retrieves all users for Admin management view."""
    users_col = getattr(app.state, "users_collection", None)
    if not users_col:
        raise HTTPException(status_code=500, detail="Users collection not available.")
    
    user_list = []
    # Fetch all users, excluding the sensitive hashed_password
    cursor = users_col.find({}, {"hashed_password": 0})
    async for user_doc in cursor:
        user_list.append(user_doc)
        
    return user_list

@app.patch("/admin/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    role_update: RoleUpdate,
    current_user: Dict = Depends(get_current_admin)
):
    """Allows an Admin to manually change a user's role."""
    users_col = getattr(app.state, "users_collection", None)
    if not users_col:
        raise HTTPException(status_code=500, detail="Users collection not available.")
    
    new_role = role_update.new_role.lower()
    if new_role not in ["admin", "agent", "user"]:
        raise HTTPException(status_code=400, detail="Invalid role specified.")
        
    try:
        # Try finding by MongoDB ObjectId or external UUID 'id' field
        is_valid_object_id = len(user_id) == 24 and ObjectId.is_valid(user_id)
        query_id = ObjectId(user_id) if is_valid_object_id else user_id
        
        update_result = await users_col.update_one(
            {"$or": [{"_id": query_id}, {"id": user_id}]},
            {"$set": {"role": new_role}}
        )

        if update_result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found.")
            
        logging.info(f"Admin {current_user['email']} updated user {user_id} role to {new_role}")
        return {"id": user_id, "new_role": new_role, "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating user role: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user role.")

# ----------------------------------------
# END ADMIN DASHBOARD ENDPOINTS
# ----------------------------------------


# -------------------------
# Chat Logic Endpoint (Main)
# -------------------------
@app.post("/chat", response_model=ChatResponse)
async def chat_interaction(
    chat_req: ChatRequest,
    current_user: Optional[Dict] = Depends(get_current_user) # Inject current user here
):
    # Retrieve authenticated user's email or default to unknown
    user_email = current_user.get("email") if current_user else "anonymous@example.com"
    
    logging.debug(f"Received Chat Request from {user_email}: {chat_req.model_dump()}") 
    
    user_query = chat_req.user_query
    session_id = chat_req.session_id
    customer_id = chat_req.customer_profile.customer_id
    
    # 0. Check for sensitive financial PII (security layer)
    if SENSITIVE_FINANCE_PATTERN.search(user_query) and chat_req.domain == "finance":
        bot_response = "I cannot process sensitive financial account details like balances or passwords through chat. Please contact our secure phone line."
        # --- MODIFIED HISTORY SAVE ---
        await save_chat_history_message(session_id, "user", user_query, user_email, {"is_sensitive": True})
        await save_chat_history_message(session_id, "bot", bot_response, user_email, {"source": "Security Filter"})
        return ChatResponse(bot_response=bot_response, case_status="blocked")

    # 1. Analyze Sentiment
    sentiment = analyze_sentiment(user_query) 
    
    # 2. Check Global History Cache (first-pass resolution)
    cached_answer = await get_history_answer(user_query)
    if cached_answer:
        # Cache hit - Resolve instantly, no new ticket, no RAG needed.
        # --- MODIFIED HISTORY SAVE ---
        await save_chat_history_message(session_id, "user", user_query, user_email)
        await save_chat_history_message(session_id, "bot", cached_answer, user_email, {"source": "Global Cache"})
        return ChatResponse(
            bot_response=cached_answer,
            case_status="resolved",
            sentiment_detected=sentiment,
            predicted_domain="cache",
            intent_confidence=1.0,
            intent_source="cache"
        )
        
    # 3. Classify Intent/Domain
    predicted_domain, confidence, source = await classify_intent(user_query) 
    
    # 4. Check for Critical/Urgent Issues (Using the stricter, new logic)
    is_critical = check_critical_issue(user_query, sentiment)
    
    # 5. KB Lookup
    kb_answer = await get_kb_answer(user_query, predicted_domain)
    
    bot_response = None
    source_type = None
    
    if kb_answer:
        bot_response = kb_answer
        source_type = "KB"
        logging.info("➡️ KB Match found.")
    elif gemini_api_key:
        # 6. Generate Response using RAG/Gemini
        try:
            bot_response = await generate_bot_response(
                user_query, chat_req.conversation_history, predicted_domain, customer_id
            )
            source_type = "Gemini"
        except Exception as e:
            logging.error(f"Gemini generation failed: {e}")
            bot_response = "I couldn't generate a response. A human agent needs to step in."
            source_type = "Fallback"
    else:
        bot_response = "I am a simple bot and require manual agent assistance for complex queries."
        source_type = "Fallback"

    # 7. Escalation & Ticket Creation Logic
    
    # A. Case 1: Critical Issue detected OR Bot cannot answer (internal self-check)
    if is_critical or should_escalate(bot_response):
        # Determine specific reason for logging/ticket subject
        failure_reason = "CRITICAL ISSUE (High Severity)" if is_critical else "BOT INCAPABLE"
        
        ticket_id = await create_mongo_ticket(
            customer_id=customer_id,
            subject=f"Urgent: {predicted_domain} - {user_query[:50]}",
            description=f"Conversation: {user_query} | Bot response: {bot_response}",
            domain=predicted_domain,
            failure_reason=failure_reason
        )
        
        final_response = (
            f"Thank you, your issue has been **immediately escalated** to a human agent "
            f"due to its critical nature ({failure_reason}). "
            f"Your reference ticket ID is **{ticket_id}**. We apologize for the inconvenience."
        ) if ticket_id else "Critical issue detected, but failed to create a ticket."
        
        case_status = "escalated"
        case_id = ticket_id
        
        # HISTORY EXCLUSION APPLIED HERE
        
        return ChatResponse(
            bot_response=final_response,
            case_status=case_status,
            case_id=case_id,
            sentiment_detected=sentiment,
            predicted_domain=predicted_domain,
            intent_confidence=confidence,
            intent_source=source,
        )

    # B. Case 2: Successful Automated Resolution (KB or Gemini)
    if source_type in ["KB", "Gemini"]:
        
        # Save message pair to history 
        # --- MODIFIED HISTORY SAVE ---
        await save_chat_history_message(session_id, "user", user_query, user_email)
        await save_chat_history_message(session_id, "bot", bot_response, user_email, {"source": source_type})

        return ChatResponse(
            bot_response=bot_response,
            case_status="resolved",
            case_id=None,
            faq_suggestion=kb_answer if source_type == "Gemini" and kb_answer else None,
            sentiment_detected=sentiment,
            predicted_domain=predicted_domain,
            intent_confidence=confidence,
            intent_source=source,
        )
    
    # C. Case 3: Pure Fallback 
    final_response = bot_response
    # Save message pair to history
    # --- MODIFIED HISTORY SAVE ---
    await save_chat_history_message(session_id, "user", user_query, user_email)
    await save_chat_history_message(session_id, "bot", final_response, user_email, {"source": source_type})
    
    return ChatResponse(
        bot_response=final_response,
        case_status="resolved", 
        sentiment_detected=sentiment,
        predicted_domain=predicted_domain,
        intent_confidence=confidence,
        intent_source=source,
    )