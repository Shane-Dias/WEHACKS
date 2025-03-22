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

from django.core.serializers.json import DjangoJSONEncoder
from django.utils.timezone import now, make_aware
@api_view(['GET'])
def advanced_incident_analysis(request):
    try:
        print("Started function")
        
        try:
            months = int(request.query_params.get('months', 12))
            if months <= 0:
                return Response({"error": "Invalid months parameter"}, status=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            return Response({"error": "Invalid months parameter"}, status=status.HTTP_400_BAD_REQUEST)

        start_date = now() - timedelta(days=30 * months)
        print("Before filter")
        
        queryset = Incidents.objects.filter(reported_at__gte=start_date)
        print(f"Queryset count: {queryset.count()}")
        print("Start")

        analytics = {
            'response_time_analysis': list(
                queryset
                .values('incidentType', 'severity')
                .annotate(
                    avg_score=Cast(Avg('score'), FloatField()),
                    total_incidents=Count('id'),
                    avg_resolution_time=Cast(
                        Avg(
                            Case(
                                When(
                                    resolved_at__isnull=False,
                                    then=ExpressionWrapper(
                                        F('resolved_at') - F('reported_at'),
                                        output_field=DurationField()
                                    )
                                ),
                                default=None,
                                output_field=DurationField(),
                            )
                        ),
                        FloatField()
                    )
                )
                .order_by('incidentType', 'severity')
            ),
            
            'monthly_trends': list(
                queryset
                .annotate(month=TruncMonth('reported_at'))
                .values('month')
                .annotate(
                    total_incidents=Count('id'),
                    high_severity=Count('id', filter=Q(severity='high')),
                    medium_severity=Count('id', filter=Q(severity='medium')),
                    low_severity=Count('id', filter=Q(severity='low')),
                    resolved_count=Count('id', filter=Q(status='resolved'))
                )
                .annotate(
                    resolution_rate=Cast(
                        F('resolved_count') * 100.0 / Cast(F('total_incidents'), FloatField()),
                        FloatField()
                    )
                )
                .order_by('month')
            ),
            
            'hourly_distribution': list(
                queryset
                .annotate(hour=ExtractHour('reported_at'))
                .values('hour')
                .annotate(
                    incident_count=Count('id'),
                    high_severity_count=Count('id', filter=Q(severity='high')),
                    avg_response_score=Cast(Avg('score'), FloatField())
                )
                .order_by('hour')
            ),
            
            'risk_hotspots': list(
                queryset
                .values('location')
                .annotate(
                    incident_density=Count('id'),
                    high_severity_count=Count('id', filter=Q(severity='high')),
                    avg_response_score=Cast(Avg('score'), FloatField()),
                    resolved_count=Count('id', filter=Q(status='resolved'))
                )
                .annotate(
                    resolution_rate=Cast(
                        F('resolved_count') * 100.0 / Cast(F('incident_density'), FloatField()),
                        FloatField()
                    )
                )
                .order_by('-incident_density')[:10]
            ),
            
            'incident_type_analysis': list(
                queryset
                .values('incidentType')
                .annotate(
                    total_count=Count('id'),
                    high_severity=Count('id', filter=Q(severity='high')),
                    medium_severity=Count('id', filter=Q(severity='medium')),
                    low_severity=Count('id', filter=Q(severity='low')),
                    avg_response_score=Cast(Avg('score'), FloatField()),
                    resolved_count=Count('id', filter=Q(status='resolved'))
                )
                .annotate(
                    resolution_rate=Cast(
                        F('resolved_count') * 100.0 / Cast(F('total_count'), FloatField()),
                        FloatField()
                    )
                )
                .order_by('-total_count')
            ),
            
            'weekly_pattern': list(
                queryset
                .annotate(weekday=ExtractWeekDay('reported_at'))
                .values('weekday')
                .annotate(
                    total_incidents=Count('id'),
                    avg_severity=Cast(
                        Avg(
                            Case(
                                When(severity='high', then=Value(3)),
                                When(severity='medium', then=Value(2)),
                                When(severity='low', then=Value(1)),
                                output_field=FloatField(),
                            )
                        ),
                        FloatField()
                    ),
                    resolved_count=Count('id', filter=Q(status='resolved'))
                )
                .annotate(
                    resolution_rate=Cast(
                        F('resolved_count') * 100.0 / Cast(F('total_incidents'), FloatField()),
                        FloatField()
                    )
                )
                .order_by('weekday')
            ),
            
            'emergency_services_summary': list(
                queryset
                .values('incidentType')
                .annotate(
                    total_incidents=Count('id'),
                    police_involved=Count('police_station', filter=Q(police_station__isnull=False)),
                    fire_involved=Count('fire_station', filter=Q(fire_station__isnull=False)),
                    hospital_involved=Count('hospital_station', filter=Q(hospital_station__isnull=False)),
                    multi_agency_response=Count('id', filter=Q(
                        police_station__isnull=False,
                        fire_station__isnull=False
                    ) | Q(
                        police_station__isnull=False,
                        hospital_station__isnull=False
                    ) | Q(
                        fire_station__isnull=False,
                        hospital_station__isnull=False
                    ))
                )
                .order_by('incidentType')
            )
        }
        
        # Calculate overall statistics separately to handle type conversion properly
        total_incidents = queryset.count()
        analytics['overall_statistics'] = {
            'total_incidents': total_incidents,
            'resolution_rate': float(
                queryset.filter(status='Resolved').count() * 100.0 / total_incidents
                if total_incidents > 0 else 0
            ),
            'avg_response_score': float(
                queryset.aggregate(avg_score=Cast(Avg('score'), FloatField()))['avg_score'] or 0
            ),
            'high_severity_percentage': float(
                queryset.filter(severity='high').count() * 100.0 / total_incidents
                if total_incidents > 0 else 0
            ),
            'multi_agency_percentage': float(
                queryset.filter(
                    Q(police_station__isnull=False) |
                    Q(fire_station__isnull=False) |
                    Q(hospital_station__isnull=False)
                ).distinct().count() * 100.0 / total_incidents
                if total_incidents > 0 else 0
            )
        }
        
        print("Done")
        return Response(analytics, status=status.HTTP_200_OK)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return Response({
            'error': 'Analysis failed',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        
from django.views import View

class UserDetailView(View):
    def get(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        user_data = {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "phone_number": user.phone_number,
            "address": user.address,
            "aadhar_number": user.aadhar_number,
            "emergency_contact1": user.emergency_contact1,
            "emergency_contact2": user.emergency_contact2,
            "date_joined": user.date_joined.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return Response(user_data)
    
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db.models import Count, Avg
from django.db.models.functions import TruncMonth, ExtractMonth, ExtractYear
from django.utils import timezone
from datetime import timedelta
import datetime

@api_view(['GET'])
def get_incident_statistics(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return Response(
            {"error": "Authorization header missing or malformed"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Extract and validate the token
        token_str = auth_header.split(' ')[1]
        token = AccessToken(token_str)
        user = get_object_or_404(User, id=token['user_id'])
    except Exception:
        return Response(
            {"error": "Invalid or expired token"},
            status=status.HTTP_401_UNAUTHORIZED
        )
    # Get date range from query params or default to last 30 days
    days = int(request.GET.get('days', 30))
    start_date = timezone.now() - timedelta(days=days)
    
    # Get user's incidents
    user_incidents = Incidents.objects.filter(
        reported_by=token['user_id']   ,
        reported_at__gte=start_date
    )
    
    # Incident types distribution
    incident_types = list(user_incidents.values('incidentType')
        .annotate(count=Count('id'))
        .order_by('-count'))
    
    # Severity distribution
    severity_dist = list(user_incidents.values('severity')
        .annotate(count=Count('id'))
        .order_by('severity'))
    
    # Status distribution
    status_dist = list(user_incidents.values('status')
        .annotate(count=Count('id'))
        .order_by('status'))
    
    # Monthly trend - using SQLite compatible approach
    monthly_incidents = user_incidents.annotate(
        year=ExtractYear('reported_at'),
        month=ExtractMonth('reported_at')
    ).values('year', 'month').annotate(
        count=Count('id')
    ).order_by('year', 'month')

    # Convert to the format expected by the frontend
    monthly_trend = []
    for entry in monthly_incidents:
        month_date = datetime.date(year=entry['year'], month=entry['month'], day=1)
        monthly_trend.append({
            'month': month_date.isoformat(),
            'count': entry['count']
        })
    
    # Score trend
    score_trend = []
    for entry in monthly_incidents:
        month_scores = user_incidents.filter(
            reported_at__year=entry['year'],
            reported_at__month=entry['month']
        )
        avg_score = month_scores.aggregate(Avg('score'))['score__avg'] or 0
        month_date = datetime.date(year=entry['year'], month=entry['month'], day=1)
        score_trend.append({
            'month': month_date.isoformat(),
            'avg_score': round(avg_score, 2)
        })
    
    return Response({
        'incident_types': incident_types,
        'severity_distribution': severity_dist,
        'status_distribution': status_dist,
        'monthly_trend': monthly_trend,
        'score_trend': score_trend,
        'total_incidents': user_incidents.count(),
        'average_score': user_incidents.aggregate(Avg('score'))['score__avg'] or 0
    })