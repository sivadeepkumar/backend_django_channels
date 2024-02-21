import jwt 
from jwt.exceptions import InvalidTokenError,ExpiredSignatureError 
from rest_framework.authentication import BaseAuthentication
from  rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from django.contrib.auth import get_user_model
from datetime import datetime,timedelta
from jwt import InvalidTokenError, ExpiredSignatureError, decode  
import logging 

User = get_user_model()
logger = logging.getLogger(__name__)
class JWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        token = self.extract_token(request=request)
        if token is None:
            return None
        
        try:
            # import pdb 
            # pdb.set_trace()
            # payload = jwt.decode(token,settings.SECRET_KEY,algorithm="HS256")
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            # pdb.set_trace()
            user_id = payload['id']
            
            user = User.objects.get(id=user_id)
            return user
        
        except InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            raise AuthenticationFailed("Invalid Token")
        
        except ExpiredSignatureError as e:
            logger.error(f"Expired token: {e}")
            raise AuthenticationFailed("Token has expired")
        
        except User.DoesNotExist:
            logger.error("User does not exist")
            raise AuthenticationFailed("User does not exist")




    def verify_token(self,payload):
        if "exp" not in payload:
            raise InvalidTokenError("Token has no expiration")
        
        exp_timestamp = payload["exp"]
        current_timestamp = datetime.utcnow().timestamp()

        if current_timestamp > exp_timestamp:
            raise ExpiredSignatureError("Token has Expired")


    def extract_token(self,request):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer"):
            return auth_header.split(" ")[1]
        return None


    @staticmethod
    def generate_token(payload):
        # import pdb 
        # pdb.set_trace()
        expiration = datetime.utcnow() + timedelta(hours=24)
        payload["exp"] = expiration
        token = jwt.encode(payload=payload,key=settings.SECRET_KEY,algorithm = "HS256")
        return token
    
