import time
from flask import Flask, request, session, jsonify, Blueprint,current_app
from langchain_community.llms import Ollama
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

faq_chat = Blueprint("faq_chat", __name__)

@faq_chat.route('/chat', methods=["POST"])
def llm_query():
    try:
        content = request.get_json()
        
        if not content:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
        
        query = content.get("query")
        
        if not query or len(query) < 2:
            return jsonify({"status": "error", "message": "Please input more characters"}), 400

        generate_prompt = PromptTemplate(
            template="""
            
            <|begin_of_text|>
            
            <|start_header_id|>system<|end_header_id|> 
            
            You are an expert assistant specializing in malware analysis. Your primary focus is to provide short and concise information about malwares. 
            This application is build to analyse the following types of malwares:
            1. RedLine Stealer
            2. Downloader
            3. Remote Access Trojans (RATs)
            4. Banking Trojans
            5. Snake Keylogger
            6. Spyware
            Always provide accurate, helpful, and focused information about various types of malware.
            <|eot_id|>
            
            <|start_header_id|>user<|end_header_id|>
            
            Question: {question} 
            Answer: 
            
            <|eot_id|>
            
            <|start_header_id|>assistant<|end_header_id|>""",
            input_variables=["question"],
        )

        if 'conversation_history' not in session:
            session['conversation_history'] = []

        session['conversation_history'].append(HumanMessage(content=query))

        current_app.logger.info("STARTED llama3")
        current_app.logger.info(f"User asks: {query}")
        
        llm = Ollama(model='llama3.2:1b', temperature=0)

        chain = generate_prompt | llm | StrOutputParser()

        start = time.time()
        response = chain.invoke({"question": query})
        end = time.time()

        time_taken = round(end - start, 2)
        current_app.logger.info(f"Time taken: {time_taken} seconds")
        
        session['conversation_history'].append(AIMessage(content=response))

        return jsonify({
            "status": "success",
            "response": response.strip(),
            "time_taken": time_taken
        })

    except Exception as e:
        current_app.logger.error(f"An error occurred: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "An internal server error occurred",
            "error": str(e)
        }), 500

@faq_chat.route('/reset-chat', methods=["POST"])
def reset_conversation():
    try:
        session.pop('conversation_history', None)
        return jsonify({
            "status": "success",
            "message": "Conversation reset successfully"
        })
    except Exception as e:
        current_app.logger.error(f"An error occurred while resetting the conversation: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "An error occurred while resetting the conversation",
            "error": str(e)
        }), 500