from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from django.urls import reverse
from backend import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
from .tokens import generate_token
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from .forms import CSVUploadForm
from datetime import datetime, timedelta
from django.utils.crypto import get_random_string
from .models import UserToken
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

import matplotlib.pyplot as plt
import joblib
import os
import base64
import io
import pandas as pd

def home(request):
    return render(request,"authentication/index.html")

def signup(request):
    if request.method == "POST":
        email = request.POST["email"]
        first_name = request.POST["first_name"]
        last_name = request.POST["last_name"]
        password = request.POST["password"]
        confirm_password = request.POST["confirm_password"]

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Invalid email address.")
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('signup')

        if password != confirm_password:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('signup')

        myuser = User.objects.create_user(username=email, email=email, password=password)
        myuser.first_name = first_name
        myuser.last_name = last_name
        myuser.is_active = False
        myuser.save()

        # Welcome Email
        subject = "Welcome to NextGen Retail Login!!"
        message = "Hello " + myuser.first_name + "!! \n" + "Welcome to NextGen Retail!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\n"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ NextGen Retail - Login!!"
        message2 = render_to_string('authentication/email_confirmation.html', {

            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        send_mail(email_subject, message2, from_email, to_list, fail_silently=True)

        return render(request, 'authentication/login_msg.html')

    return render(request, "authentication/signup.html")

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        myuser.delete()
        return render(request,'authentication/activation_failed.html')
    
def signin(request):
    if request.method == "POST":
        email = request.POST["email"]  # Change username to email
        password = request.POST["password"]
        user = authenticate(username= email, password=password)  # Change username to email
        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect('predict')
            else:
                messages.error(request, "Please activate your account in order to login.")
                return redirect("signin")
        else:
            messages.error(request, "Bad Credentials! Please try again.")
            return redirect("signin")
    return render(request, "authentication/signin.html")

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity')
            if last_activity:
                # Check if the session has expired
                timeout_seconds = settings.SESSION_COOKIE_AGE
                if datetime.now() - last_activity > timedelta(seconds=timeout_seconds):
                    # Session has expired, logout the user
                    logout(request)
                    messages.info(request, 'You have been logged out due to inactivity.')
                    return redirect('signin')

        # Update last activity timestamp in the session
        request.session['last_activity'] = datetime.now()
        response = self.get_response(request)
        return response

@login_required
def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("home")

@login_required
def change_password(request):
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')

        user = request.user

        # Check if the old password is correct
        if not user.check_password(old_password):
            messages.error(request, 'Incorrect old password. Please try again.')
            return redirect('change_password')

        # Check if the new passwords match
        if new_password != confirm_new_password:
            messages.error(request, 'New passwords do not match. Please try again.')
            return redirect('change_password')

        # Set the new password
        user.set_password(new_password)
        user.save()

        # Update session to prevent logout
        update_session_auth_hash(request, user)
        logout(request)
        messages.success(request, 'Your password was successfully updated!')
        return redirect('signin')
    else:
        return render(request, 'authentication/change_password.html')

@login_required
def profile_update(request):
    if request.method == "POST":
        user = request.user
        
        new_email = request.POST.get("new_email")
        confirm_email = request.POST.get("confirm_email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")

        # Validate new email address
        try:
            validate_email(new_email)
        except ValidationError:
            messages.error(request, "Invalid email address.")
            return redirect('profile_update')

        if new_email != confirm_email:
            messages.error(request, "Email addresses do not match.")
            return redirect('profile_update')

        # Check if the new email is already taken
        if User.objects.exclude(pk=user.pk).filter(email=new_email).exists():
            messages.error(request, "Email address is already in use.")
            return redirect('profile_update')

        # Update user profile and set is_active to False
        user.username = new_email
        user.email = new_email
        user.first_name = first_name
        user.last_name = last_name
        user.is_active = False  # Set is_active to False
        user.save()

        # Send activation email to the updated email
        current_site = get_current_site(request)
        from_email = settings.EMAIL_HOST_USER
        to_list = [user.email]
        mail_subject = 'Activate your account'
        message = render_to_string('authentication/email_confirmation.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })

        send_mail(mail_subject, message, from_email, to_list, fail_silently=True)
        
        logout(request)
        messages.success(request, 'An activation link has been sent to your new email address. Please check your email to activate your account.')
        
        return render(request, 'authentication/email_change_msg.html')

    return render(request, "authentication/profile.html")

def contact_us(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        message = request.POST.get('message')
        send_mail(
            'Query for NextGen Retail Website',
            f'Email: {email}\n\nMessage: {message}',
            'nextgenretail65@gmail.com',
            ['nextgenretail65@gmail.com'],  # Replace with your email address
            fail_silently=False,
        )
        # Redirect to a thank you page or back to the home page
        messages.success(request,"You Query has been submitted.")
        return HttpResponseRedirect(reverse('home'))
    else:
        # If the request method is not POST, render the home page wth an eror message
        messages.error(request, "Can't send the mail, please try again!")
        return render(request, 'authentication/index.html')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        user = User.objects.filter(email=email).first()
        if user:
            # Generate a unique token and save it to the user model
            token = get_random_string(length=32)
            user_token = UserToken.objects.create(email=email, reset_password_token=token)
             # Get the current site's domain
            current_site = get_current_site(request)
            domain = current_site.domain
            
            # Construct the reset link dynamically
            reset_link = f"http://{domain}/reset_password/{token}/"
            send_mail('Reset Password', f'Click the following link to reset your password: {reset_link}',
                      settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
            return render(request, 'authentication/password_reset_done.html')
        else:
            return render(request, 'authentication/password_reset_failed.html')
    return render(request, 'authentication/forgot_password.html')

def reset_password(request, token):
    user_token = UserToken.objects.filter(reset_password_token=token).first()
    if not user_token:
        # Handle invalid or expired token
        return render(request, 'authentication/password_reset_invalid.html')
    if request.method == 'POST':
        new_password = request.POST.get('new_password', '')
        confirm_new_password = request.POST.get('confirm_new_password', '')
        if new_password != confirm_new_password:
            error_message = "Passwords do not match."
            return render(request, 'authentication/reset_password.html', {'error_message': error_message, 'token': token})
        # Update the user's password and reset the token
        user = User.objects.get(email=user_token.email)
        user.set_password(new_password)
        user.save()

        user_token.delete()
        return render(request, 'authentication/password_reset_complete.html')
    return render(request, 'authentication/reset_password.html', {'token': token})

@login_required
def delete_user(request):
    if request.method == 'POST':
        if request.POST.get('confirm') == 'yes':
            user = request.user
            user.delete()
            messages.success(request, "Your account has been deleted successfully!")
            return redirect('home')
        else:
            return redirect('predict')
    return render(request, 'authentication/delete_user_confirmation.html')

@login_required
def prediction(request):
    # Initialize variables
    predicted_amount_plot = None
    pie_chart = None
    bar_graph = None
    line_graph = None
    revenue_prediction_graph = None
    images_present = False
    user_first_name = request.user.first_name if request.user.first_name else ""

    if request.method == 'POST':
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            csv_file = request.FILES['csv_file']
            
            if not csv_file:
                messages.error(request, "No file uploaded.")
                return redirect('predict')
           
            if not csv_file.name.endswith('.csv'):
                messages.error(request, "Please upload a CSV file.")
                return redirect('predict')
 
            try:
                df = pd.read_csv(csv_file)
            except Exception as e:
                messages.error(request, f'Error reading CSV: {e}')
                return redirect('predict')
                           
            model_path = settings.ML_MODEL_PATH
 
            if not os.path.exists(model_path):
                messages.error(request, "Model file not found.")
                return redirect('predict')
                 
            try:
                model = joblib.load(model_path)
            except Exception as e:
                messages.error(request, f'Error loading model: {e}')
                return redirect('predict')
             
            try:
                # Predict TotalAmount
                df['PredictedTotalAmount'] = model.predict(df[['CustomerID', 'ProductID', 'Quantity']])
                
                # Create a scatter plot of Predicted TotalAmount vs Actual TotalAmount
                plt.figure(figsize=(8, 6))
                plt.scatter(df['TotalAmount'], df['PredictedTotalAmount'])
                plt.xlabel('Actual TotalAmount')
                plt.ylabel('Predicted TotalAmount')
                plt.title('Actual vs Predicted TotalAmount')
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png')
                buffer.seek(0)
                predicted_amount_plot = base64.b64encode(buffer.getvalue()).decode('utf-8')
                buffer.close()
 
                # Create additional graphs
                # Pie Chart
                pie_data = df['Category'].value_counts()
                plt.figure(figsize=(8, 6))
                plt.pie(pie_data, labels=pie_data.index, autopct='%1.1f%%')
                plt.title('Category Distribution')
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png')
                buffer.seek(0)
                pie_chart = base64.b64encode(buffer.getvalue()).decode('utf-8')
                buffer.close()
 
                # Bar Graph
                bar_data = df.groupby('ProductName')['Quantity'].sum().sort_values(ascending=False).head(10)
                plt.figure(figsize=(10, 10))
                bar_data.plot(kind='bar')
                plt.xlabel('Product Name')
                plt.ylabel('Total Quantity Sold')
                plt.title('Top 10 Products by Quantity Sold')
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png')
                buffer.seek(0)
                bar_graph = base64.b64encode(buffer.getvalue()).decode('utf-8')
                buffer.close()
 
                # Line Graph
                line_data = df.groupby('PurchaseDate')['TotalAmount'].sum()
                plt.figure(figsize=(10, 6))
                line_data.plot(kind='line', marker='o')
                plt.xlabel('Purchase Date')
                plt.ylabel('Total Amount')
                plt.title('Total Amount Over Time')
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png')
                buffer.seek(0)
                line_graph = base64.b64encode(buffer.getvalue()).decode('utf-8')
                buffer.close()
 
                # Predict Revenue for the next 6 months
                latest_date = df['PurchaseDate'].max()
                latest_date = datetime.strptime(latest_date.split()[0], '%Y-%m-%d')  # Extract date part and convert to datetime object
                prediction_dates = [(latest_date + timedelta(days=30 * i)).strftime('%Y-%m-%d') for i in range(1, 7)]
 
                predicted_revenue = []
                for date in prediction_dates:
                    last_data_point = df.iloc[-1]
                    predicted_revenue.append(model.predict([[last_data_point['CustomerID'], last_data_point['ProductID'], last_data_point['Quantity']]])[0])
 
                # Create a line graph for predicted revenue vs next 6 months
                plt.figure(figsize=(10, 7))
                plt.plot(prediction_dates, predicted_revenue, marker='o')
                plt.xlabel('Date')
                plt.ylabel('Predicted Revenue')
                plt.title('Predicted Revenue for Next 6 Months')
                plt.xticks(rotation=45)
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png')
                buffer.seek(0)
                revenue_prediction_graph = base64.b64encode(buffer.getvalue()).decode('utf-8')
                buffer.close()
               
                images_present = True
            except Exception as e:
                messages.error(request, f'Error in prediction or data processing: {e}')
                return redirect('predict')
    else:
        form = CSVUploadForm()
        
    return render(request, 'authentication/dashboard.html', {
        'user_first_name': user_first_name,
        'form': form,
        'pie_chart': pie_chart,
        'bar_graph': bar_graph,
        'line_graph': line_graph,
        'predicted_amount_plot': predicted_amount_plot,
        'revenue_prediction_graph': revenue_prediction_graph,
        'images_present': images_present,
    })
