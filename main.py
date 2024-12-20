from flask import Flask, request, send_file, jsonify
from google.cloud import storage
import io
from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth



PHOTO_BUCKET= "tarpaulin-cmt-jb-portfolio"
COURSES = 'courses'
USERS = 'users'
AVATAR = 'avatar'
STUDENTS = 'students'
ENROLLMENT = 'enrollment'
COURSE_INSTRUCTOR = 'course_instructor'
USER_AVATAR = 'user_avatar'

CLIENT_ID = '6ham7PycrY0SDBJRTLrDypqXgPQpvBBv'
CLIENT_SECRET = 'BvdqDHDEra8A7HJ0Ehr0__34_bft1Gw9mzh6oq_aXUV-EkurJ83IYgUzvFZwKpVg'
DOMAIN = 'dev-yfv44873yxjene04.us.auth0.com'

MISSING_FIELDS = { "Error": "The request body is invalid" }
UNAUTHORIZED_ERR = { "Error": "Unauthorized" }
UNAUTHORIZED_ACCESS = { "Error": "You don't have permission on this resource" }
MISSING_FILE_ERR = { "Error": "Not found" }
ENROLLMENT_DATA_ERR = { "Error": "Enrollment data is invalid" }

ALGORITHMS = ["RS256"]



app = Flask(__name__)
oauth = OAuth(app)
client = datastore.Client()


auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)



@app.route('/' + USERS + '/login', methods=['POST'])
def user_login():
    content = request.get_json()
    if 'username' not in content or 'password' not in content:
        return MISSING_FIELDS, 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    r = r.json()
    
    if ('error' in r):
        return UNAUTHORIZED_ERR, 401
    
    resp = {}
    resp["token"] = r['id_token']
    return resp


@app.route('/' + USERS, methods=['GET'])
def get_users():
    try:
        payload = verify_jwt(request)
        # get the user's information, and check if 
        # they have the role of an admin. if not, return an error.

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]
        if user['role'] != 'admin':
            return UNAUTHORIZED_ACCESS, 403

        query = client.query(kind=USERS)
        users = list(query.fetch())
        for u in users:
            u['id'] = u.key.id

        return users
    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401


@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
        # get the user's information, and check if 
        # they have the role of an admin. if not, return an error.

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        cur_user = list(query.fetch())[0]

        user_key = client.key(USERS, user_id)
        searched_user = client.get(key=user_key)

        if searched_user == None or ((cur_user['role'] != 'admin') and (cur_user.key.id != searched_user.key.id)):
            print(searched_user, cur_user['role'], cur_user.key.id, searched_user.key.id)
            return UNAUTHORIZED_ACCESS, 403

        searched_user['id'] = searched_user.key.id


        user_avatar_query = client.query(kind=USER_AVATAR)
        user_avatar_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
        results = list(user_avatar_query.fetch())

        if len(results) == 1:
            searched_user['avatar_url'] = f'{request.url}/{AVATAR}'
        
        courses = []

        if cur_user['role'] == 'admin':
            return searched_user
        
        elif cur_user['role'] == 'instructor':
            course_instructor_query = client.query(kind=COURSE_INSTRUCTOR)
            course_instructor_query.add_filter(filter=PropertyFilter('instructor_id', '=', user_id))
            courses_taught = list(course_instructor_query.fetch())
            for c in courses_taught:
                courses.append(f'{request.root_url}{COURSES}/{c['course_id']}')
            searched_user['courses'] = courses

        else:
            enrollment_query = client.query(kind=ENROLLMENT)
            enrollment_query.add_filter(filter=PropertyFilter('student_id', '=', user_id))
            courses_enrolled = list(enrollment_query.fetch())
            for c in courses_enrolled:
                courses.append(f'{request.root_url}{COURSES}/{c['course_id']}')
            searched_user['courses'] = courses
        
        return searched_user

    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['POST'])
def store_avatar(user_id):
    try:
        
        # Any files in the request will be available in request.files object
        # Check if there is an entry in request.files with the key 'file'
        if 'file' not in request.files:
            print(request.files)
            return MISSING_FIELDS, 400

        payload = verify_jwt(request)

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]

        if user.key.id != user_id:
            return UNAUTHORIZED_ACCESS, 403
        # Set file_obj to the file sent in the request
        file_obj = request.files['file']
        # Create a storage client
        storage_client = storage.Client()
        # Get a handle on the bucket
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        # Create a blob object for the bucket with the name of the file
        blob = bucket.blob(file_obj.filename)
        # Position the file_obj to its beginning
        file_obj.seek(0)

        # check if there is already an avatar for the user. if so, delete
        # the old avatar and insert the new one.
        user_avatar_query = client.query(kind=USER_AVATAR)
        user_avatar_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
        results = list(user_avatar_query.fetch())

        if len(results) == 1:
            # remove the current file and then delete this result.
            user_avatar = results[0]
            old_avatar_id = user_avatar['avatar_id']
            blobs = storage_client.list_blobs(PHOTO_BUCKET)
            for b in blobs:
                if old_avatar_id == b.id:
                    b.delete()
                    break
            client.delete(user_avatar)


        blob.content_type = "image/png"
        # Upload the file into Cloud Storage
        blob.upload_from_file(file_obj)
        # update our user_avatar table with the id from the new file_obj.
        user_avatar_key = client.key(USER_AVATAR)
        new_user_avatar = datastore.Entity(key=user_avatar_key)
        new_user_avatar.update({
            'user_id': user_id,
            'avatar_id': blob.id
        })
        client.put(new_user_avatar)


        resp = {}
        resp['avatar_url'] = request.url
        return resp
    
    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401
        print(a)
        return UNAUTHORIZED_ERR, 401


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['GET'])
def get_avatar(user_id):
    try:
        payload = verify_jwt(request)
        
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]

        if user.key.id != user_id:
            return UNAUTHORIZED_ACCESS, 403

        storage_client = storage.Client()
        # Create a file object in memory using Python io package
        file_obj = io.BytesIO()


        user_avatar_query = client.query(kind=USER_AVATAR)
        user_avatar_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
        results = list(user_avatar_query.fetch())

        if len(results) == 1:
            blobs = storage_client.list_blobs(PHOTO_BUCKET)
            avatar_id = results[0]['avatar_id']
            for blob in blobs:
                # find the avatar for this user_id.
                if avatar_id == blob.id:
                    # Download the file from Cloud Storage to the file_obj variable
                    blob.download_to_file(file_obj)
                    # Position the file_obj to its beginning
                    file_obj.seek(0)
                    # Send the object as a file in the response with the correct MIME type and file name
                    return send_file(file_obj, mimetype='image/png', download_name=blob.name)
        else:
            return MISSING_FILE_ERR, 404

    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401
        print(a)
        return UNAUTHORIZED_ERR, 401


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
        
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]

        if user.key.id != user_id:
            return UNAUTHORIZED_ACCESS, 403

        storage_client = storage.Client()
        user_avatar_query = client.query(kind=USER_AVATAR)
        user_avatar_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
        results = list(user_avatar_query.fetch())
        
        if len(results) == 1:
            # remove the current file and then delete this result.
            user_avatar = results[0]
            old_avatar_id = user_avatar['avatar_id']
            blobs = storage_client.list_blobs(PHOTO_BUCKET)
            for b in blobs:
                if old_avatar_id == b.id:
                    b.delete()
                    break
            client.delete(user_avatar)
            
            return '', 204

        else: 
            return MISSING_FILE_ERR, 404

    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401
        print(a)
        return UNAUTHORIZED_ERR, 401



@app.route('/' + COURSES, methods=['POST'])
def post_courses():
    try:
        payload = verify_jwt(request)
        content = request.get_json()
        # get the user's information, and check if 
        # they have the role of an admin. if not, return an error.

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]
        if user['role'] != 'admin':
            return UNAUTHORIZED_ACCESS, 403

        instructor_key = client.key(USERS, int(content['instructor_id']))
        searched_instructor = client.get(key=instructor_key)
        if searched_instructor['role'] != 'instructor':
            return MISSING_FIELDS, 400

        new_key = client.key(COURSES)
        new_course = datastore.Entity(key=new_key)
        new_course.update({
            'subject': content['subject'],
            'number': int(content['number']),
            'title': content['title'],
            'term': content['term'],
            'instructor_id': int(content['instructor_id'])
        })
        # puts the new entity into the datastore.
        client.put(new_course)
        new_course['id'] = new_course.key.id
        new_course['self'] = f'{request.url}/{new_course['id']}'

        # update the courses of the instructor.
        instructor_key = client.key(COURSE_INSTRUCTOR)
        new_course_instructor = datastore.Entity(key=instructor_key)
        new_course_instructor.update({
            'instructor_id': new_course['instructor_id'],
            'course_id': new_course['id']
        })
        client.put(new_course_instructor)

        return (new_course, 201)

    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401
        print(a)
        return UNAUTHORIZED_ERR, 401

    except Exception as e:
        print(e)
        return MISSING_FIELDS, 400


@app.route('/' + COURSES, methods=['GET'])
def get_courses(offset=0, limit=3):

    if len(request.args) == 2:
        limit = int(request.args['limit'])
        offset = int(request.args['offset'])

    query = client.query(kind=COURSES)
    query.order = ['subject']
    query_params = request.args
    l_iterator = query.fetch(limit=limit, offset=offset)
    pages = l_iterator.pages
    results = list(next(pages))


    for r in results:
        r['id'] = r.key.id
        r['self'] = f'{request.base_url}/{r["id"]}'

    reply = {}
    reply['courses'] = results
    reply['next'] = f'{request.base_url}?offset={offset+limit}&limit={limit}'

    return reply


@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    if course == None:
        return MISSING_FILE_ERR, 404
    else:
        course['id'] = course.key.id
        course['self'] = request.url
        return course


@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    try:
        
        payload = verify_jwt(request)
        content = request.get_json()
        # get the user's information, and check if 
        # they have the role of an admin. if not, return 403

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]
        if user['role'] != 'admin':
            return UNAUTHORIZED_ACCESS, 403

        # check if the course exists. if not, return 403.
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)

        if course == None:
            return MISSING_FILE_ERR, 403
        else:

            # this means the course exists, the user is a valid admin, and a valid jwt token is provided.
            # now we need to validate the instructor_id to see if a valid instructor is found with that id.
            if 'instructor_id' in content:
                content['instructor_id'] = int(content['instructor_id'])
                instructor_key = client.key(USERS, content['instructor_id'])
                searched_instructor = client.get(key=instructor_key)
                if searched_instructor == None or ((searched_instructor['role'] != 'instructor')):
                    return UNAUTHORIZED_ACCESS, 400

                # then we need to check if the current instructor is different from
                # the new instructor. if so, we update the courses for both.
                if course['instructor_id'] != content['instructor_id']:
                    enrollment_query = client.query(kind=COURSE_INSTRUCTOR)
                    enrollment_query.add_filter(filter=PropertyFilter('instructor_id', '=', course['instructor_id']))
                    enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
                    i_new = list(enrollment_query.fetch())[0]

                    i_new.update({
                        'instructor_id': content['instructor_id']
                    })
                    client.put(i_new)

            if 'number' in content:
                content['number'] = int(content['number'])

            new_data = {}
            for key in content:
                new_data[key] = content[key]
            course.update(new_data)
            client.put(course)

            course['id'] = course.key.id
            course['self'] = request.url

            return course

    except AuthError as a:
        print(a)
        # JWT should be invalid.
        return UNAUTHORIZED_ERR, 401




@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
        
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]

        if user['role'] != 'admin':
            return UNAUTHORIZED_ACCESS, 403
        
        # check if the course exists. if not, return 403.
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)

        if course == None:
            return UNAUTHORIZED_ACCESS, 403

        # find all students enrolled in the
        # course, and delete those listings.
        enrollment_query = client.query(kind=ENROLLMENT)
        enrollment_query.add_filter('course_id', '=', course_id)
        enrollments = list(enrollment_query.fetch())

        for e in enrollments:
            client.delete(e)
            
        # then we find the instructor associated with 
        # this course and remove this course from their list.
        course_instructor_query = client.query(kind=COURSE_INSTRUCTOR)
        course_instructor_query.add_filter('course_id', '=', course_id)
        course_instructor_query.add_filter('instructor_id', '=', course['instructor_id'])
        course_instructor = list(course_instructor_query.fetch())[0]
        client.delete(course_instructor)

        client.delete(course_key)
        # once all courses with this course id are removed, then we're done.
        return '', 204

    except AuthError as a:
        if a.error['code'] == 'invalid_header':
            return UNAUTHORIZED_ERR, 401
        print(a)
        return UNAUTHORIZED_ERR, 401


@app.route('/' + COURSES + '/<int:course_id>/' + STUDENTS, methods=['PATCH'])
def update_enrollment(course_id):
    try:
        
        payload = verify_jwt(request)
        content = request.get_json()
        # get the user's information, and check if 
        # they have the role of an admin or they are the
        # instructor of the course.

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]

        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)

        if course == None:
            return MISSING_FILE_ERR, 403

        if (user['role'] != 'admin') and (course['instructor_id'] != user.key.id):
            return UNAUTHORIZED_ACCESS, 403

        # This means the current user has permission to update the 
        # current course. Now we check the body of the request to see if it's valid.

        # any element in add cannot also be in remove.
        add_students = content['add']
        remove_students = content['remove']
        for s in add_students:
            if s in remove_students:
                return ENROLLMENT_DATA_ERR, 409
        
        # then for each student from add and remove, check if they're a student.
        # if not, return 409.
        all_students = add_students.copy() + remove_students.copy()
        for s_id in all_students:
            s_key = client.key(USERS, s_id)
            s_data = client.get(key=s_key)

            if s_data['role'] != 'student':
                return ENROLLMENT_DATA_ERR, 409
        
        # now that our data is verified, we update the enrollment for each
        # student.
        for s_id in add_students:
            # check if the student is already enrolled. If not, update
            # enrollment with the new student/course.
            enrollment_query = client.query(kind=ENROLLMENT)
            enrollment_query.add_filter(filter=PropertyFilter('student_id', '=', s_id))
            enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
            results = list(enrollment_query.fetch())

            # if no enrollment is found, then an update is needed.
            if len(results) == 0:
                enrollment_key = client.key(ENROLLMENT)
                new_enrollment = datastore.Entity(key=enrollment_key)
                new_enrollment.update({
                    'student_id': s_id,
                    'course_id': course_id
                })
                client.put(new_enrollment)
        
        for s_id in remove_students:
            enrollment_query = client.query(kind=ENROLLMENT)
            enrollment_query.add_filter(filter=PropertyFilter('student_id', '=', s_id))
            enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
            results = list(enrollment_query.fetch())
            
            if len(results) == 1:
                enrollment = results[0]
                client.delete(enrollment)

        return ''

    except AuthError as a:
        print(a)
        # JWT should be invalid.
        return UNAUTHORIZED_ERR, 401


@app.route('/' + COURSES + '/<int:course_id>/' + STUDENTS, methods=['GET'])
def get_enrollment(course_id):
    try:
        payload = verify_jwt(request)
        # get the user's information, and check if 
        # they have the role of an admin or they are the
        # instructor of the course.

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())[0]

        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)

        if course == None:
            return MISSING_FILE_ERR, 403

        if (user['role'] != 'admin') and (course['instructor_id'] != user.key.id):
            return UNAUTHORIZED_ACCESS, 403

        # we have valid access, so we obtain all 
        # students enrolled in the course.
        query = client.query(kind=ENROLLMENT)
        query.add_filter('course_id', '=', course_id)
        course_enrollments = list(query.fetch())
        results = []

        for e in course_enrollments:
            results.append(e['student_id'])
        
        return results

    except AuthError as a:
        print(a)
        # JWT should be invalid.
        return UNAUTHORIZED_ERR, 401




if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)