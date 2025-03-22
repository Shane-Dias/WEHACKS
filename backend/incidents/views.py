from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework.response import Response
from geopy.distance import great_circle
from utils.comments import contains_cuss_words, is_spam
from incidents.models import DisasterReliefStations, FireStations, PoliceStations
from .serializers import CommentSerializer, IncidentSerializer, UserSerializer
from incidents.models import DisasterReliefStations, FireStations, PoliceStations, Admin
from .serializers import IncidentSerializer
from django.core.mail import send_mail
import requests
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import check_password
from twilio.rest import Client
import json
from geopy.distance import great_circle
from .models import Incidents, FireStations, PoliceStations, User, Comment, Hospital, NGO
from .serializers import IncidentSerializer
from rest_framework.views import APIView
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import logging
logger = logging.getLogger(__name__)
from rest_framework import generics, status
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_google_genai import ChatGoogleGenerativeAI
from rest_framework import viewsets, status
from langchain.schema.output_parser import StrOutputParser
from rest_framework.parsers import JSONParser
from tenacity import wait_exponential
import re
from django.db.models import (
    Avg, Count, Q, FloatField, F, 
    ExpressionWrapper, Case, When, 
    OuterRef, Subquery, IntegerField
)
from django.db.models.functions import (
    ExtractWeekDay, TruncMonth, 
    ExtractHour, ExtractYear
)
from django.db.models import (
    Avg, Case, Count, F, FloatField, IntegerField, Q, Value, When, ExpressionWrapper, DurationField
)
from django.db.models.functions import (
    Cast, Extract, ExtractHour, ExtractWeekDay, TruncMonth
)
from django.utils import timezone
from datetime import timedelta

model = ChatGoogleGenerativeAI(
                model="gemini-1.5-flash",
                api_key="AIzaSyDv7RThoILjeXAryluncDRZ1QeFxAixR7Q",
                max_retries=3,
                retry_wait_strategy=wait_exponential(multiplier=1, min=4, max=10)
            )

@api_view(['GET'])
def latest_incidents(request):
    incidents = Incidents.objects.order_by('-reported_at')[:9]  # Adjust the number of incidents as needed
    serializer = IncidentSerializer(incidents, many=True)
    return Response(serializer.data)

class SignUpView(APIView):
    def post(self, request):
        data = request.data

        # Validate required fields
        required_fields = [
            "firstName", "lastName", "email", "phoneNumber",
            "address", "aadharNumber", "emergencyContact1",
            "emergencyContact2", "password"
        ]
        for field in required_fields:
            if not data.get(field):
                return Response({field: f"{field} is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check for unique constraints
        if User.objects.filter(email=data["email"]).exists():
            return Response({"email": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Save user
        try:
            user = User.objects.create(
                first_name=data["firstName"],
                last_name=data["lastName"],
                email=data["email"],  # Use email as username
                password=make_password(data["password"])  # Hash the password
            )

            # Add custom fields if you're using a custom User model
            user.phone_number = data["phoneNumber"]
            user.address = data["address"]
            user.aadhar_number = data["aadharNumber"]
            user.emergency_contact1 = data["emergencyContact1"]
            user.emergency_contact2 = data["emergencyContact2"]
            user.save()

            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)

        except IntegrityError:
            return Response({"error": "An error occurred while creating the user."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Input validation
        if not email or not password:
            return Response({
                "error": "Both email and password are required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Determine if it's an admin or regular user login
            if email.endswith("@admin.com"):
                user = get_object_or_404(Admin, email=email)
                user_type = "admin"
            else:
                user = get_object_or_404(User, email=email)
                user_type = "user"

            # Verify password
            if not check_password(password, user.password):
                return Response({
                    "error": "Invalid credentials"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Login successful",
                "user_type": user_type,
                "user_id": user.id,
                "email": user.email,
                "tokens": {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh)
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": "Invalid credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        

class form_report(APIView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.llm = model
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """
            Analyze the incident report and determine its severity level strictly based on the given description, using the following criteria:

            high:
            Immediate threat to life
            Multiple casualties
            Large-scale property damage
            Ongoing dangerous situation
            
            medium:
            Non-life-threatening injuries
            Significant property damage
            Potential for situation escalation
            Missing persons cases

            low:
            Minor incidents
            No injuries
            Minor property damage
            Non-emergency situations
            
            You must return only one of these words: high, medium, or low based on the information provided. If details are unclear, make the best possible classification rather than asking for more details. Do not include explanations—return only the classification.
            """),
            ("human", "{user_input}")
        ])
        self.chain = self.prompt | self.llm | StrOutputParser()

    def post(self, request, *args, **kwargs):
        """Handles reporting of incidents"""
        try:
            user = self.authenticate_user(request)
            data = request.data.copy()
            data['severity'] = self.chain.invoke({"user_input": data.get("description", "")}).strip()
            print("data recieved",data)
            # Validate location data
            location = dict(self.validate_location(data.get("location")))
            if not location:
                return Response({"error": "Invalid location data"}, status=status.HTTP_400_BAD_REQUEST)
            
            lat, lon = location["latitude"], location["longitude"]
            print("location gotten")
            # Check for similar existing incidents
            existing_incident = self.find_similar_incident(data, lat, lon)
            if existing_incident:
                existing_incident.count += 1
                existing_incident.save()
                self.notify_existing_incident(existing_incident)
                return Response({
                    "message": "Incident reported successfully!",
                    "incident_id": existing_incident.id,
                    "severity": data['severity']
                }, status=status.HTTP_201_CREATED)
            match = re.search(r'\{.*\}', data['location'], re.DOTALL)
            if match:
                json_string = match.group()
                data['location'] = json.loads(json_string)
            print(data)
            serializer = IncidentSerializer(data=data)
            if serializer.is_valid():
                print("serializer is valid")
                incident = serializer.save(reported_by=user)
                self.assign_nearest_stations(incident, lat, lon)
                return Response({
                    "message": "Incident reported successfully!",
                    "incident_id": incident.id,
                    "severity": data['severity']
                }, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def authenticate_user(self, request):
        """Authenticate user or fallback to anonymous"""
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                token_str = auth_header.split(' ')[1]
                token = AccessToken(token_str)
                return User.objects.get(id=token['user_id'])
            except Exception:
                pass  # Fallback to anonymous

        return User.objects.get_or_create(
            email='anonymous@example.com',
            defaults={
                'first_name': 'Anonymous',
                'last_name': 'User',
                'phone_number': '0000000000',
                'address': 'Anonymous',
                'aadhar_number': '000000000000',
                'emergency_contact1': '0000000000',
                'emergency_contact2': '0000000000',
                'password': 'anonymous'
            }
        )[0]

    def validate_location(self, location):
        """Ensures location is valid"""
        if isinstance(location, str):
            try:
                location = json.loads(location)
            except json.JSONDecodeError:
                return None

        if not isinstance(location, dict) or "latitude" not in location or "longitude" not in location:
            return None

        lat, lon = location["latitude"], location["longitude"]
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            return None
        
        return location

    def find_similar_incident(self, data, lat, lon):
        """Check for existing similar incidents within 50 meters & 1 hour"""
        recent_incidents = Incidents.objects.filter(incidentType=data.get("incidentType"))
        for incident in recent_incidents:
            if great_circle((lat, lon), (incident.location["latitude"], incident.location["longitude"])).meters <= 50:
                print("Under 50 metres")
                if abs(data.get("reported_at", timezone.now()) - incident.reported_at) <= timedelta(hours=1):
                    print("Under 1 hour")
                    if self.is_similar_incident(data["description"], incident.description):
                        return incident
        return None

    def is_similar_incident(self, new_description, previous_description):
        """Check if two incidents have similar descriptions using LLM"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", "Based on the description of the two incidents, return only 'True' if they are similar, otherwise 'False'."),
            ("human", "{newdata} \n {previousdata}")
        ])
        chain = prompt | model | StrOutputParser()
        return chain.invoke({"newdata": new_description, "previousdata": previous_description}) == "True"

    def notify_existing_incident(self, incident):
        """Send notification if an incident is reported again"""
        stations = [incident.police_station, incident.fire_station, incident.hospital_station]
        for station in filter(None, stations):
            subject = "Incident has been reported by another user"
            message = f"Another user has reported the same incident (ID: {incident.id}). Please investigate."
            send_email_example(subject, message, station.email)

    def assign_nearest_stations(self, incident, lat, lon):
        """Assigns nearest police, fire, and hospital stations to the incident"""

        station_map = {
            'Domestic Violence': [PoliceStations],
            'Child Abuse': [PoliceStations],
            'Sexual Harassment': [PoliceStations],
            'Stalking': [PoliceStations],
            'Human Trafficking': [PoliceStations],
            'Fire': [FireStations, PoliceStations, Hospital],
            'Theft': [PoliceStations],
            'Accident': [PoliceStations, Hospital],
            'Missing Persons': [PoliceStations],
            'Medical Emergency': [Hospital],
            'Other': [PoliceStations]  
        }

        station_models = station_map.get(incident.incidentType, [])
        user_location = (lat, lon)

        for station_model in station_models:
            stations = station_model.objects.all()
            if stations.exists():
                nearest_station = min(stations, key=lambda station: great_circle(user_location, (station.latitude, station.longitude)).km)
                
                if station_model == PoliceStations:
                    incident.police_station = nearest_station
                elif station_model == FireStations:
                    incident.fire_station = nearest_station
                elif station_model == Hospital:
                    incident.hospital_station = nearest_station

                # Notify nearest station
                self.notify_new_incident(nearest_station, incident)

        incident.save()

