
import os
import uuid
import magic
import pefile
from utils.main import db
from models.user import User
from user_agents import parse
from models.scans import ScanHistory
from sqlalchemy.exc import SQLAlchemyError
from flask import jsonify, g, request, current_app, Blueprint
from routes.training import predict
webapp = Blueprint("frontend_pages", __name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'exe', 'dll', 'sys', 'zip','pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_pe_file(file_path):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    return file_type in ['application/x-dosexec', 'application/x-msdownload']

'''Get the pefile headers from the file'''
def get_pefile_headers(original_filename, hashed_filename, file_path):
    try:
        pe = pefile.PE(file_path)
        
        # Extract DOS Header
        dos_header = {
            'e_magic': pe.DOS_HEADER.e_magic,
            'e_cblp': pe.DOS_HEADER.e_cblp,
            'e_cp': pe.DOS_HEADER.e_cp,
            'e_crlc': pe.DOS_HEADER.e_crlc,
            'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
            'e_minalloc': pe.DOS_HEADER.e_minalloc,
            'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
            'e_ss': pe.DOS_HEADER.e_ss,
            'e_sp': pe.DOS_HEADER.e_sp,
            'e_csum': pe.DOS_HEADER.e_csum,
            'e_ip': pe.DOS_HEADER.e_ip,
            'e_cs': pe.DOS_HEADER.e_cs,
            'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
            'e_ovno': pe.DOS_HEADER.e_ovno,
            'e_oemid': pe.DOS_HEADER.e_oemid,
            'e_oeminfo': pe.DOS_HEADER.e_oeminfo,
            'e_lfanew': pe.DOS_HEADER.e_lfanew
        }

        # Extract File Header
        file_header = {
            'Machine': pe.FILE_HEADER.Machine,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
            'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics
        }

        # Extract Optional Header
        optional_header = {
            'Magic': pe.OPTIONAL_HEADER.Magic,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            'Reserved1': pe.OPTIONAL_HEADER.Reserved1
        }
        
        results = {
            'DOS_HEADER': dos_header,
            'FILE_HEADER': file_header,
            'OPTIONAL_HEADER': optional_header
        }
        
        # Prepare scan history data
        scan_data = {
            'file_name': original_filename,
            'hashed_name': hashed_filename,
            'details': {**dos_header, **file_header, **optional_header}
        }
        
        # Check if user is logged in
        if hasattr(g, 'user') and g.user and g.user.id:
            scan_data['user_id'] = g.user.id
          
        # Collect and track user data about browser
        user_agent = parse(request.user_agent.string)
        scan_data['request_info'] = {
            'ip_address': request.remote_addr,
            'user_agent': str(user_agent),
            'browser': user_agent.browser.family,
            'os': user_agent.os.family,
            'device': user_agent.device.family
            }
        
        try:
            scan = ScanHistory(**scan_data)
            db.session.add(scan)
            db.session.commit()
        except SQLAlchemyError as db_error:
            db.session.rollback()
            print(f"Database error: {str(db_error)}")
            # Log this error for admin review
            
        return {**dos_header, **file_header, **optional_header}
    
    except pefile.PEFormatError as e:
        return {'error': f"Not a valid PE file - {str(e)}"}
    except Exception as e:
        print(f"Unexpected error in get_pefile_headers: {str(e)}")
        # Log this error for admin review
        return {'error': "An unexpected error occurred while processing the file"}
    
'''Scan a file and get malware analysis'''
@webapp.route('/scan/file', methods=['POST'])
def upload_file():
    token = request.headers.get('Authorization', None)
    if token:
        token = token.split()[1]
        user = User.verify_auth_token(token)
        g.user = user
        
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    file = request.files['file']
    
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        # Generate a secure random filename
        filename = str(uuid.uuid4())
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(file_path)
            
            # Check if it's actually a PE file
            if not is_pe_file(file_path):
                os.remove(file_path)
                return jsonify({'error': 'Not a valid PE file'}), 400
            
            # Extract PE file headers
            headers = get_pefile_headers(original_filename=file.filename,hashed_filename=filename,file_path=file_path)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            # Clean up: remove the uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)
        
        return jsonify(predict(headers))
    else:
        return jsonify({'error': 'File type not allowed'}), 400
    
##Routes
@webapp.route('/scan_file', methods=['POST'])
def scan_file():
    return "Response from the malware scan"
    
@webapp.route('/scan_url', methods=['POST'])
def scan_url():
    return {
        "malware_analysed" : 200,
        "total_scans": 300
    }

