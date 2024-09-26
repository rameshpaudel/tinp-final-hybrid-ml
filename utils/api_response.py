'''JSON API responses for error and success '''
def success_message(message):
    return {'message': message, 'success': True}

def success_response(data, message = None):
    if message is not None:
        return {'data': data, 'message': message, 'success': True}
    return {'data': data, 'success': True}

def error_response(message):
    return {'message': message, 'success': False}
