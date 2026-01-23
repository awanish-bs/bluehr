import google.generativeai as genai
import os
import json
from app.models import Document
import PyPDF2
import docx
import io
from app.utils.blob_storage import get_blob_service_client

class ChatbotService:
    def __init__(self):
        # Configure Gemini API
        from flask import current_app
        import os
        
        # Try to get API key from Flask Config first, then environment
        api_key = current_app.config.get('GEMINI_API_KEY') or os.environ.get('GEMINI_API_KEY')
        
        # Sanitize and log key presence (safely)
        if api_key:
            api_key = api_key.strip()
            prefix = api_key[:4]
            suffix = api_key[-4:]
            print(f"DEBUG: ChatbotService init - API Key exists! (Starts with: {prefix}..., Ends with: ...{suffix})")
        else:
            print("DEBUG: ChatbotService init - API Key is MISSING!")
        
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set.")
            
        try:
            genai.configure(api_key=api_key)
            # Using gemini-1.5-flash for better performance and speed
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            print("DEBUG: Gemini 1.5 Flash model initialized successfully.")
        except Exception as e:
            print(f"ERROR: Failed to initialize Gemini model: {str(e)}")
            raise e
        
    def get_system_prompt(self):
        """
        Easily editable system prompt for Gemini.
        Modify this prompt to change chatbot behavior.
        """
        return """
You are an HR Policy Assistant chatbot for a company.

Your responsibilities:
1. Answer questions about company HR policies, leave policies, and general HR procedures
2. Base your answers ONLY on the provided policy documents
3. NEVER discuss, reveal, or reference anything related to:
   - Payslips
   - Salary information
   - Compensation details
   - Individual employee earnings
   - Personal employee data
4. If asked about restricted topics, politely decline and say: "I can only help with HR policies and procedures. For salary or personal information, please contact HR directly."
5. If the answer is not in the provided documents, clearly state: "I don't have information about that in the available policy documents. Please contact HR for more details."
6. Be helpful, professional, and concise
7. Always mention which policy document you're referencing when possible

Context from policy documents:
{documents_context}

User Question: {user_question}

Provide a clear, professional answer based only on the policy documents above.
"""
    
    def extract_text_from_blob(self, blob_url, filename):
        """Extract text from PDF, DOCX, or TXT files stored in Azure Blob Storage"""
        try:
            # Get blob service client
            blob_service_client = get_blob_service_client()
            
            # Extract blob name from URL
            # blob_url format: https://accountname.blob.core.windows.net/container/blobname
            blob_name = blob_url.split('/documents/')[-1]
            
            # Download blob to memory
            blob_client = blob_service_client.get_blob_client(container="documents", blob=blob_name)
            blob_data = blob_client.download_blob().readall()
            
            # Determine file extension
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            
            if ext == 'pdf':
                pdf_file = io.BytesIO(blob_data)
                reader = PyPDF2.PdfReader(pdf_file)
                text = ' '.join([page.extract_text() for page in reader.pages])
                return text
            elif ext in ['docx', 'doc']:
                docx_file = io.BytesIO(blob_data)
                doc = docx.Document(docx_file)
                return ' '.join([para.text for para in doc.paragraphs])
            elif ext == 'txt':
                return blob_data.decode('utf-8')
        except Exception as e:
            print(f"Error extracting text from {filename}: {str(e)}")
        
        return ''
    
    def extract_policy_documents(self):
        """Get all policy documents excluding salary/payslip related ones"""
        # Excluded keywords for document names and types
        excluded_keywords = ['payslip', 'salary', 'compensation', 'payroll', 
                           'pay slip', 'pay-slip', 'wage', 'earnings', 'pay_slip']
        
        # Get all documents
        all_documents = Document.query.all()
        
        # Filter out salary/payslip related documents
        policy_documents = []
        for doc in all_documents:
            filename_lower = doc.filename.lower()
            original_lower = doc.original_filename.lower()
            file_type_lower = (doc.file_type or '').lower()
            
            # Check if document name or type contains excluded keywords
            if not any(keyword in filename_lower for keyword in excluded_keywords) and \
               not any(keyword in original_lower for keyword in excluded_keywords) and \
               not any(keyword in file_type_lower for keyword in excluded_keywords):
                policy_documents.append(doc)
        
        return policy_documents
    
    def build_context(self, documents):
        """Build context string from policy documents"""
        context_parts = []
        
        print(f"DEBUG: Building context from {len(documents)} documents")
        
        for i, doc in enumerate(documents):
            print(f"DEBUG: Processing document {i+1}/{len(documents)}: {doc.original_filename}")
            # Extract text content from document stored in blob storage
            content = self.extract_text_from_blob(doc.blob_url, doc.original_filename)
            
            if content:  # Only add if we could extract content
                # Limit content to prevent token overflow
                max_content_length = 4000
                truncated_content = content[:max_content_length]
                if len(content) > max_content_length:
                    truncated_content += "... [content truncated]"
                
                context_parts.append(
                    f"Document: {doc.original_filename}\n"
                    f"Type: {doc.file_type or 'N/A'}\n"
                    f"Uploaded: {doc.upload_date.strftime('%Y-%m-%d')}\n"
                    f"Content:\n{truncated_content}\n"
                    f"---"
                )
        
        return "\n\n".join(context_parts)
    
    def get_response(self, user_question):
        """
        Get chatbot response using Gemini
        Returns: (response_text, referenced_document_ids)
        """
        print(f"DEBUG: get_response for: {user_question}")
        # Get policy documents
        documents = self.extract_policy_documents()
        print(f"DEBUG: Found {len(documents)} policy documents")
        
        if not documents:
            return "I don't have any policy documents to reference. Please contact HR directly.", []
        
        # Build context
        documents_context = self.build_context(documents)
        
        if not documents_context:
            return "I'm having trouble reading the policy documents. Please contact HR directly.", []
        
        # Build full prompt
        full_prompt = self.get_system_prompt().format(
            documents_context=documents_context,
            user_question=user_question
        )
        
        # Get response from Gemini
        try:
            print(f"DEBUG: Sending prompt to Gemini (Prompt length: {len(full_prompt)})...")
            response = self.model.generate_content(full_prompt)
            
            if not response or not hasattr(response, 'text'):
                print(f"DEBUG: AI Response: {response}")
                return "I received an empty response from the AI. Please try again.", []
                
            response_text = response.text
            print("DEBUG: Gemini response received successfully.")
            
            # Track which documents were referenced
            doc_ids = [doc.id for doc in documents]
            
            return response_text, doc_ids
            
        except Exception as e:
            error_message = str(e)
            print(f"ERROR: Gemini API Error: {error_message}")
            
            # Check if it's an API key error
            if any(term in error_message.upper() for term in ["API_KEY", "API KEY", "403", "401", "400"]):
                return f"The chatbot API key seems invalid or restricted. Please ensure the GEMINI_API_KEY in your .env file is correct and has the necessary permissions. Error: {error_message}", []
                
            return f"I apologize, but I encountered an error: {error_message}. Please try again or contact HR.", []
