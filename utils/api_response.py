'''JSON API responses for error and success '''
def success_response(message):
    return {'message': message, 'success': True}


def error_response(message):
    return {'message': message, 'success': False}
