import jwt
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.exceptions import ParseError, NotFound, AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from users.models import User
from . import serializers


class Me(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = serializers.PrivateUserSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        serializer = serializers.PrivateUserSerializer(
            user,
            data=request.data,
            partial=True,
        )
        if serializer.is_valid():
            user = serializer.save()
            serializer = serializers.PrivateUserSerializer(user)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class Users(APIView):

    def post(self, request):
        password = request.data.get("password")
        if not password:
            raise ParseError
        serializer = serializers.PrivateUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(password)
            user.save()
            serializer = serializers.PrivateUserSerializer(user)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class PublicUser(APIView):

    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise NotFound
        serializer = serializers.PrivateUserSerializer(user)
        return Response(serializer.data)


class JWTLogIn(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            raise ParseError
        user = authenticate(
            request,
            username=username,
            password=password,
        )
        if user:
            token = jwt.encode(
                {"pk": user.pk},
                settings.SECRET_KEY,
                algorithm="HS256",
            )
            return Response({"token": token})
        else:
            return Response({"error": "wrong password"})


class UserView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        username = request.query_params.get('username')
        if username:
            try:
                user = User.objects.get(username=username)
                serializer = serializers.PrivateUserSerializer(user)
                return Response({
                    "status": "success",
                    "detail": serializer.data
                })
            except User.DoesNotExist:
                raise NotFound({
                    "status": 404,
                    "detail": "User not found"
                })
        else:
            return Response({
                "status": 400,
                "detail": "Username Query Parameter is required"
            }, status=status.HTTP_400_BAD_REQUEST)


class LogIn(APIView):

    def get(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            raise ParseError(detail="Username and password are required")

        user = authenticate(
            request,
            username=username,
            password=password,
        )
        if user:
            login(request, user)
            return Response({
                "status": "success",
                "username": username,
            })
        else:
            raise AuthenticationFailed(detail="Invalid username or password")


class LogOut(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        username = request.user.username
        logout(request)
        return Response({
            "status": "success",
            "message": f"Goodbye, {username}!"
        })


class UserUpdate(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        email = request.data.get("email")
        phone = request.data.get("phone")

        if not old_password and not new_password and not email and not phone:
            raise ParseError("At least one field (old_password, new_password, email, phone) must be provided for update.")

        if old_password and new_password:
            if not user.check_password(old_password):
                raise ParseError("Incorrect old password.")
            user.set_password(new_password)

        if email:
            old_email = user.email
            user.email = email

        if phone:
            old_phone = user.phone
            user.phone = phone

        user.save()

        # 변경된 사용자 정보 및 수정된 필드를 반환
        response_data = {
            "status": "success",
            "username": user.username,
            "updated_fields": {}
        }
        if 'old_email' in locals() and old_email != user.email:
            response_data["updated_fields"]["email"] = {
                "old_value": old_email,
                "new_value": user.email
            }
        if 'old_phone' in locals() and old_phone != user.phone:
            response_data["updated_fields"]["phone"] = {
                "old_value": old_phone,
                "new_value": user.phone
            }

        return Response(response_data, status=201)


class UserDelete(APIView):

    permission_classes = [IsAuthenticated]

    def delete(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required to delete the user."}, status=400)

        user = authenticate(request, username=username, password=password)

        if user is None:
            return Response({"error": "Incorrect username or password."}, status=401)

        if not user == request.user:
            return Response({"error": "You are not authorized to delete this user."}, status=403)

        deleted_username = user.username

        user.delete()
        return Response({
            "status": "success",
            "deleted_username": deleted_username,
            "message": "User and related data deleted successfully."
        })