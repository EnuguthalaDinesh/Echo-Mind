import os
import sys
import uuid
import re
import json
import logging
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import google.generativeai as genai
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from passlib.context import CryptContext
from jose import JWTError, jwt

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# --- MongoDB Setup ---
MONGO_URI = os.getenv("MONGODB_URI")
if not MONGO_URI:
    logging.error("MONGODB_URI not found in .env file or environment variables. Please set it.")
    mongo_client = None
    orders_collection = None
    cases_collection = None
    customers_collection = None
    users_collection = None
    logging.warning("MongoDB connection will not be available due to missing MONGODB_URI.")
else:
    try:
        mongo_client = MongoClient(MONGO_URI)
        mongo_client.admin.command('ping')
        chatbot_db = mongo_client["chatbot"]
        orders_collection = chatbot_db["orders"]
        cases_collection = chatbot_db["cases"]
        customers_collection = chatbot_db["customers"]
        users_collection = chatbot_db["users"]
        logging.info("MongoDB client initialized successfully and connected to 'chatbot' database.")
    except Exception as e:
        logging.critical(f"Failed to connect to MongoDB at {MONGO_URI}: {e}")
        mongo_client = None
        orders_collection = None
        cases_collection = None
        customers_collection = None
        users_collection = None
        logging.warning("MongoDB connection will not be available due to connection error.")

# --- Password Hashing and JWT Configuration ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-for-jwt")
ALGORITHM = "HS256"

# --- Google Gemini API Configuration ---
gemini_api_key = os.getenv("GEMINI_API_KEY")
if not gemini_api_key:
    logging.error("GEMINI_API_KEY not found in .env file or environment variables. Please set it.")
    raise RuntimeError("Error: GEMINI_API_KEY is not set. Cannot start without it.")

try:
    genai.configure(api_key=gemini_api_key)
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            logging.info(f"Gemini model available: {m.name}")
    logging.info("Google Gemini client initialized successfully.")
except Exception as e:
    logging.critical(f"Failed to initialize Google Gemini client: {e}")
    raise RuntimeError(f"Error: Could not initialize Google Gemini client. Details: {e}")

GEMINI_MODEL_NAME = 'gemini-2.5-flash'

# --- FastAPI Application Setup ---
app = FastAPI(
    title="Customer Support Chatbot Backend (Gemini Integrated)",
    description="API for handling customer support queries using Google Gemini's 1.5 Flash model, "
                "with context, history, and basic case management features, "
                "including MongoDB integration for order lookup, case memory, and long-term memory.",
    version="0.1.0"
)

# --- CORS Middleware Configuration ---
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "null"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models for Request/Response ---
class UserBase(BaseModel):
    name: str
    email: EmailStr

class UserInDB(UserBase):
    hashed_password: str
    customer_id: str

class UserRegister(UserBase):
    password: str

class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: str

class Case(BaseModel):
    case_id: str
    session_id: str
    customer_id: str
    status: str = "open"
    created_at: str
    last_updated: str
    initial_query: str
    conversation_history: List[dict] = []
    escalated: bool = False
    summary: Optional[str] = None
    domain: str = "general"

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
    shop_id_for_order_lookup: Optional[str] = None
    domain: str

class ChatResponse(BaseModel):
    bot_response: str
    case_status: str = "open"
    case_id: Optional[str] = None
    faq_suggestion: Optional[str] = None
    sentiment_detected: Optional[str] = None

class HistorySummaryRequest(BaseModel):
    session_id: str
    conversation_history: List[ChatMessage]

class HistorySummaryResponse(BaseModel):
    session_id: str
    summary: str

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CustomerId(BaseModel):
    customer_id: str

# --- Load domain-specific knowledge bases from a JSON file ---
try:
    with open('domain_questions.json', 'r') as f:
        domain_knowledge_bases = json.load(f)
    logging.info("Successfully loaded domain-specific knowledge bases from domain_questions.json")
except FileNotFoundError:
    logging.warning("domain_questions.json not found. Using a small, default knowledge base.")
    domain_knowledge_bases = {
        "general": {
            "refund status": "Refunds typically take 5-7 business days to process. Please provide your order number to check the status.",
        },
        "technical": {
            "internet not working": "Please try restarting your router and modem. If the issue persists, check the service status page for your area.",
            "installation help": "For installation assistance, please refer to your product manual or visit our online guides.",
        },
        "finance": {
            "billing inquiry": "For billing inquiries, please provide your account number. You can also check your last bill online.",
        },
        "travel": {
            "change plan": "You can change your service plan through your online account portal or by speaking with a sales representative.",
            "flight status": "You can check your flight status on the airline's website or app using your booking reference.",
        }
    }
except json.JSONDecodeError:
    logging.error("Error decoding domain_questions.json. Please check for syntax errors.")
    domain_knowledge_bases = {}

# --- Utility Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(lambda x: x.headers.get('authorization', '').split(' ')[1] if x.headers.get('authorization') else None)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if not token:
            raise credentials_exception
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = users_collection.find_one({"email": email})
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

def get_knowledge_base_info(query: str, domain: str) -> str:
    knowledge_base = domain_knowledge_bases.get(domain, {})
    for keyword, info in knowledge_base.items():
        if keyword in query.lower():
            return info
    return "No specific knowledge base article found for this query."

def analyze_sentiment(text: str) -> str:
    text_lower = text.lower()
    if any(w in text_lower for w in ["not working", "frustrated", "annoyed", "unhappy", "bad", "terrible"]):
        return "frustrated"
    elif any(w in text_lower for w in ["thank you", "resolved", "great", "happy", "good", "excellent"]):
        return "satisfied"
    return "neutral"

def determine_intent_and_urgency(query: str) -> tuple[str, str, dict]:
    intent = "general_inquiry"
    urgency = "low"
    entities = {}
    query_lower = query.lower().strip()
    greeting_patterns = [r"hi+", r"hello+", r"hey+", r"good morning", r"good afternoon", "good evening"]
    if any(re.match(pattern, query_lower) for pattern in greeting_patterns):
        return "greeting", urgency, entities
    shopid_patterns = [
        r'(?:my\s+order\s+number\s+is|order\s+number\s+is|order\s+id\s+is|shopid\s+is|id\s+is)\s*[\#]?([a-zA-Z0-9]+)',
        r'(?:shopid|orderid|tracking|ref|id)[\s:]*[\#]?([a-zA-Z0-9]+)',
        r'([a-zA-Z0-9]+)\s+(?:order|shopid|tracking|ref|id)'
    ]
    shopid_found = False
    for pattern in shopid_patterns:
        shopid_match = re.search(pattern, query_lower)
        if shopid_match:
            extracted_id = shopid_match.group(1)
            entities["shopid"] = extracted_id
            intent = "order_status"
            shopid_found = True
            break
    if not shopid_found:
        if any(w in query_lower for w in ["internet", "wifi", "connection", "network", "technical issue", "troubleshoot", "device"]):
            intent = "technical_support"
        elif any(w in query_lower for w in ["bill", "invoice", "payment", "charge", "account balance", "billing issue", "cost", "fee"]):
            intent = "billing_inquiry"
        elif "refund" in query_lower:
            intent = "refund_request"
        elif any(w in query_lower for w in ["installation", "setup", "install", "new service", "activate"]):
            intent = "installation_support"
        elif any(w in query_lower for w in ["change plan", "upgrade", "downgrade", "new plan", "service package", "contract"]):
            intent = "plan_management"
        elif any(w in query_lower for w in ["order status", "track order", "where is my order", "delivery", "shipping", "item arrived"]):
            intent = "order_status"
        elif any(w in query_lower for w in ["loan", "mortgage", "investment", "credit card", "bank account", "financial advice", "money"]):
            intent = "finance_query"
        elif any(w in query_lower for w in ["booking", "flight", "hotel", "reservation", "vacation", "tour", "travel plan", "destination", "trip"]):
            intent = "travel_hospitality_query"
        else:
            intent = "general_inquiry"
    return intent, urgency, entities

def manage_case_escalation(current_turn: int, intent: str, urgency: str, sentiment: str, escalated_in_session: bool) -> bool:
    if escalated_in_session:
        return True
    if urgency == "high" and sentiment == "frustrated":
        return True
    if current_turn > 3 and sentiment == "frustrated":
        return True
    if intent in ["technical_support", "billing_inquiry", "finance_query", "travel_hospitality_query", "order_status"] and current_turn > 2:
        return True
    return False

def get_order_details_by_id(shopid: str | None) -> str:
    if orders_collection is None:
        return "I'm so sorry, but the order lookup service is temporarily unavailable. Please try again in a little while!"
    if not shopid:
        return "It looks like a Shop ID wasn't included in your message. To check your order, please provide your Shop ID (e.g., 'What's the status of order SHOPID123?')."
    shopid_clean = shopid.strip().upper()
    if not re.fullmatch(r'^[A-Z0-9]+$', shopid_clean):
        return f"I couldn't find an order with that ID: '{shopid_clean}'. Could you double-check it for me? Shop IDs usually contain letters and numbers only."
    order = orders_collection.find_one({"shopid": shopid_clean})
    if not order:
        return f"I'm sorry, but I couldn't find an order with the ID '{shopid_clean}'. Please double-check the ID and try again, or contact our support team for more help!"
    product = order.get("product_name", "Unknown Product")
    payment = order.get("payment_status", "Unknown")
    delivery_str = order.get("delivery_date", None)
    delivery_info = "Not Available"
    if delivery_str:
        try:
            delivery_date = datetime.strptime(delivery_str, "%Y-%m-%d").date()
            today = datetime.today().date()
            days_left = (delivery_date - today).days
            if days_left > 0:
                delivery_info = f"{delivery_date.strftime('%B %d, %Y')} (expected in {days_left} days)"
            elif days_left == 0:
                delivery_info = f"{delivery_date.strftime('%B %d, %Y')} (expected today!)"
            else:
                delivery_info = f"{delivery_date.strftime('%B %d, %Y')} (was {abs(days_left)} days ago, possibly delivered or completed)"
        except ValueError:
            delivery_info = f"'{delivery_str}' (Invalid date format stored. Please contact support to correct this.)"
    return (
        f"Order found:\n"
        f"Product: {product}\n"
        f"Payment Status: {payment}\n"
        f"Estimated Delivery: {delivery_info}"
    )

# --- API Endpoints ---
@app.post("/auth/register")
async def register(user: UserRegister):
    if users_collection is None:
        raise HTTPException(status_code=503, detail="User registration service is currently unavailable.")
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=409, detail="Email already registered")
    customer_id = str(uuid.uuid4())
    hashed_password = get_password_hash(user.password)
    user_in_db = UserInDB(
        name=user.name,
        email=user.email,
        hashed_password=hashed_password,
        customer_id=customer_id
    )
    users_collection.insert_one(user_in_db.model_dump())
    return {"ok": True, "customer_id": customer_id}

@app.post("/auth/login", response_model=Token)
async def login_for_access_token(request: LoginRequest):
    if users_collection is None:
        raise HTTPException(status_code=503, detail="User login service is currently unavailable.")
    user = users_collection.find_one({"email": request.email})
    if not user or not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    if genai is None:
        raise HTTPException(status_code=503, detail="Google Gemini client is not initialized. Check server logs.")
    if cases_collection is None or customers_collection is None:
        raise HTTPException(status_code=503, detail="MongoDB collections for cases and customers are not initialized. Check server logs.")

    user_query = request.user_query
    session_id = request.session_id
    customer_id = request.customer_profile.customer_id
    shop_id_from_explicit_frontend_field = request.shop_id_for_order_lookup
    domain = request.domain

    # --- Load or Create Customer Profile (Long-Term Memory) ---
    customer_profile_from_db = customers_collection.find_one({"_id": customer_id})
    if customer_profile_from_db:
        customer_profile = CustomerProfile(**customer_profile_from_db)
        logging.info(f"Loaded existing customer profile for {customer_id}.")
    else:
        new_profile_data = request.customer_profile.model_dump()
        new_profile_data['_id'] = customer_id
        customers_collection.insert_one(new_profile_data)
        customer_profile = CustomerProfile(**new_profile_data)
        logging.info(f"Created new customer profile for {customer_id}.")

    # --- Find or Create Case (Case Memory) ---
    case_id = session_id
    current_case_data = cases_collection.find_one({"_id": case_id, "customer_id": customer_id})
    
    if not current_case_data:
        logging.info(f"Creating a new case for customer {customer_id} with session {session_id}.")
        current_case_data = {
            "_id": case_id,
            "session_id": session_id,
            "customer_id": customer_id,
            "status": "open",
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "initial_query": user_query,
            "conversation_history": [],
            "escalated": False,
            "domain": domain
        }
        cases_collection.insert_one(current_case_data)
        customers_collection.update_one({"_id": customer_id}, {"$set": {"active_case_id": case_id}})
    
    # --- Intent, Sentiment & Escalation Check ---
    intent, urgency, extracted_entities = determine_intent_and_urgency(user_query)
    user_sentiment = analyze_sentiment(user_query)
    case_history = [msg.model_dump() for msg in request.conversation_history]
    current_turn = len(case_history) // 2 + 1
    
    # --- Domain Restriction Logic ---
    domain_map = {
        "general": ["general_inquiry", "greeting"],
        "technical": ["technical_support", "installation_support", "greeting"],
        "finance": ["finance_query", "billing_inquiry", "greeting"],
        "travel": ["travel_hospitality_query", "greeting", "order_status"]
    }
    
    if intent not in domain_map.get(request.domain, []):
        if intent == "order_status" and request.domain == "general":
            pass
        elif intent == "general_inquiry" and request.domain != "general":
            pass
        else:
            return ChatResponse(
                bot_response=f"I'm sorry, but I can only help with **{request.domain.capitalize()}**-related queries here. To ask about something else, please return to the homepage and select a different chat domain!",
                case_status="closed",
                case_id=None,
                faq_suggestion=None,
                sentiment_detected="unanswered",
            )
            
    # --- Prepare Prompt for Gemini with domain-specific examples ---
    domain_prompts = {
        "general": "You are a friendly customer support assistant. Your primary task is to answer general queries. You should also answer questions about order status.",
        "technical": "You are a technical support agent. Your task is to help users with technical issues.",
        "finance": "You are a finance support agent. Your task is to answer financial queries.",
        "travel": "You are a travel assistant. Your task is to answer travel and hospitality queries.",
    }
    for q, a in domain_knowledge_bases.get(request.domain, {}).items():
        domain_prompts[request.domain] += f"\nQ: {q}\nA: {a}"
    base_system_instruction = (
        f"You are a friendly, empathetic, and professional customer support assistant. "
        f"Your expertise is strictly limited to **{request.domain}**-related customer support queries. "
        f"{domain_prompts.get(request.domain, '')}\n"
        "If a user asks something outside this domain, gently explain your scope and offer to assist with relevant topics. "
        "Maintain a conversational and approachable tone, like a helpful human agent. "
        "Be concise and actionable in your advice."
    )
    
    gemini_messages = [
        {"role": "user", "parts": [base_system_instruction]},
        {"role": "model", "parts": ["Understood. I am ready to assist customers within these topics with a helpful and friendly tone."]}
    ]
    for msg in case_history:
        gemini_role = "model" if msg['role'] == "bot" else "user"
        gemini_messages.append({"role": gemini_role, "parts": [msg['content']]})
    
    long_term_memory_summary = "N/A"
    if customer_profile.previous_interactions:
        long_term_memory_summary = "Past interactions summary:\n" + "\n".join(customer_profile.previous_interactions)
    final_llm_instruction_for_gemini = None
    if intent == "greeting" and current_turn == 1:
        final_llm_instruction_for_gemini = "The user has just started the conversation or said hello. Provide a very brief, friendly greeting and ask how you can help them today. Do NOT identify yourself as a virtual assistant or AI. Respond concisely."
    elif intent == "order_status":
        shopid_for_lookup = extracted_entities.get("shopid") or shop_id_from_explicit_frontend_field
        order_details_tool_output = get_order_details_by_id(shopid_for_lookup)
        final_llm_instruction_for_gemini = (
            f"The customer asked for order status. You've performed a lookup and the tool returned the following information:\n\n{order_details_tool_output}\n\n"
            f"Your task is to summarize this information clearly and concisely for the user, focusing on the product, payment, and delivery status. "
            f"If the tool indicates 'No order found' or an error, politely explain this and ask for a correct ID. "
            f"Maintain a warm and natural tone. Conclude by offering further assistance."
        )
    elif get_knowledge_base_info(user_query, request.domain) != "No specific knowledge base article found for this query.":
        knowledge_info = get_knowledge_base_info(user_query, request.domain)
        final_llm_instruction_for_gemini = (
            f"The user asked about '{user_query}'. You found relevant information in your knowledge base: '{knowledge_info}'. "
            f"Present this information in a friendly, helpful, and human-like way. "
            f"End by asking if that was what they were looking for or if they need more help. Be concise."
        )
    else:
        final_llm_instruction_for_gemini = (
            f"Customer Query: {user_query}\n"
            f"Customer ID: {customer_profile.customer_id}\n"
            f"Long-term memory: {long_term_memory_summary}\n"
            f"Customer's current sentiment: {user_sentiment}\n"
            f"Detected intent: {intent}. Urgency: {urgency}.\n"
            f"Extracted entities: {extracted_entities}\n"
        )
    gemini_messages.append({"role": "user", "parts": [final_llm_instruction_for_gemini]})
    try:
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        chat_session = model.start_chat(history=gemini_messages[:-1])
        response = await chat_session.send_message_async(
            gemini_messages[-1]['parts'][0],
            safety_settings={
                "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
                "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
                "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
                "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
            }
        )
        bot_response_text = response.text
        logging.info(f"Gemini API response received for session {session_id}.")
    except Exception as e:
        logging.error(f"Error calling Gemini API for session {session_id}: {e}")
        bot_response_text = "Oh dear, I seem to be having a little trouble at the moment. Please bear with me and try again in a bit, or feel free to reach out to our human support directly if it's urgent!"
        current_case_data["escalated"] = True
    should_escalate = manage_case_escalation(
        current_turn, intent, urgency, user_sentiment, current_case_data.get("escalated", False)
    )
    if should_escalate and not current_case_data.get("escalated", False):
        current_case_data["escalated"] = True
        current_case_data["status"] = "escalated_to_human"
        bot_response_text += "\n\n**Just a heads-up**: Based on our conversation, I think it might be best if a human agent steps in. I'm escalating this for you, and someone will review our chat and get in touch shortly!"
        logging.info(f"Session {session_id} officially escalated.")
    case_status = current_case_data["status"]
    case_history.append({"role": "user", "content": user_query, "timestamp": datetime.now().isoformat()})
    case_history.append({"role": "bot", "content": bot_response_text, "timestamp": datetime.now().isoformat()})
    cases_collection.update_one(
        {"_id": case_id},
        {"$set": {
            "conversation_history": case_history,
            "last_updated": datetime.now().isoformat(),
            "status": case_status,
            "escalated": current_case_data["escalated"]
        }}
    )
    return ChatResponse(
        bot_response=bot_response_text,
        case_status=case_status,
        case_id=case_id,
        faq_suggestion=get_knowledge_base_info(user_query, request.domain),
        sentiment_detected=user_sentiment,
    )

@app.get("/history/{customer_id}", response_model=List[Case])
async def get_chat_history(customer_id: str):
    if cases_collection is None:
        raise HTTPException(status_code=503, detail="MongoDB cases collection is not initialized.")
    user_cases = cases_collection.find({"customer_id": customer_id}).sort("last_updated", -1)
    if not user_cases:
        raise HTTPException(status_code=404, detail=f"No chat history found for customer ID: {customer_id}")
    cases = []
    for case_data in user_cases:
        case_data['case_id'] = case_data['_id']
        cases.append(Case(**case_data))
    return cases
    
@app.get("/history/{customer_id}/{session_id}", response_model=List[ChatMessage])
async def get_conversation_history(customer_id: str, session_id: str):
    if cases_collection is None:
        raise HTTPException(status_code=503, detail="MongoDB cases collection is not initialized.")
    case_data = cases_collection.find_one({"_id": session_id, "customer_id": customer_id})
    if not case_data:
        raise HTTPException(status_code=404, detail=f"Conversation not found for session ID: {session_id}")
    history = [ChatMessage(**msg) for msg in case_data.get("conversation_history", [])]
    return history

@app.post("/resolve_case")
async def resolve_case_endpoint(case_id: str):
    if cases_collection is None or customers_collection is None:
        raise HTTPException(status_code=503, detail="MongoDB collections for cases and customers are not initialized.")
    case = cases_collection.find_one({"_id": case_id})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    if case.get("status") in ["resolved", "closed"]:
        return {"message": f"Case {case_id} is already resolved."}
    history_string = " ".join([m['content'] for m in case['conversation_history']])
    summary_prompt = (
        f"Provide a concise, 5-10 word title for this customer support chat conversation. "
        f"Focus on the main issue. The conversation is as follows: {history_string}"
    )
    try:
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        response = await model.generate_content_async(summary_prompt)
        summary_text = response.text.strip().replace('"', '')
    except Exception as e:
        logging.error(f"Failed to generate summary for case {case_id}: {e}")
        summary_text = f"Case {case_id} was resolved on {datetime.now().isoformat()}. The primary issue was not automatically summarized."
    customers_collection.update_one(
        {"_id": case['customer_id']},
        {"$push": {"previous_interactions": summary_text}, "$unset": {"active_case_id": ""}}
    )
    cases_collection.update_one(
        {"_id": case_id},
        {"$set": {"status": "resolved", "summary": summary_text}}
    )
    logging.info(f"Case {case_id} resolved and summarized in customer's long-term memory.")
    return {"message": f"Case {case_id} resolved and summarized in customer's long-term memory."}

@app.post("/summarize_case", response_model=HistorySummaryResponse)
async def summarize_case_endpoint(request: HistorySummaryRequest):
    if genai is None:
        raise HTTPException(status_code=503, detail="Google Gemini client is not initialized.")
    history_string = " ".join([m.content for m in request.conversation_history])
    summary_prompt = (
        f"Provide a concise, 5-10 word title for this customer support chat conversation. "
        f"Focus on the main issue. The conversation is as follows: {history_string}"
    )
    try:
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        response = await model.generate_content_async(summary_prompt)
        summary_text = response.text.strip().replace('"', '')
    except Exception as e:
        logging.error(f"Failed to generate summary for session {request.session_id}: {e}")
        summary_text = "Untitled Chat"
    return HistorySummaryResponse(session_id=request.session_id, summary=summary_text)