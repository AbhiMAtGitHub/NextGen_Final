from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.urls import reverse
from backend import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from .forms import CSVUploadForm
from datetime import datetime, timedelta
from django.utils.crypto import get_random_string
from .models import UserToken
import joblib
import os
import io
import json
import pandas as pd
import matplotlib
matplotlib.use('Agg')
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Image
import matplotlib.pyplot as plt


def home(request):
    return render(request,"authentication/index.html")

def signup(request):
    if request.method == "POST":
        email = request.POST["email"]
        first_name = request.POST["first_name"]
        last_name = request.POST["last_name"]
        password = request.POST["password"]
        confirm_password = request.POST["confirm_password"]

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
        
        # Welcome Email
        subject = "Welcome to NextGen Retail Login!!"
        message = "Hello " + myuser.first_name + "!! \n" + "Welcome to NextGen Retail!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\n"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Generate activation token
        uidb64 = urlsafe_base64_encode(force_bytes(myuser.pk))
        token = default_token_generator.make_token(myuser)

        # Build activation URL
        domain = get_current_site(request).domain
        activate_url = f"http://{domain}{reverse('activate_email', kwargs={'uidb64': uidb64, 'token': token})}"

        # Send activation email
        subject = "Confirm your Email @ NextGen Retail - Login!!"
        message = render_to_string('authentication/email_confirmation.html', {
            'user': myuser,
            'activate_url': activate_url,
        })
        myuser.email_user(subject, message)
        myuser.save()

        return render(request, 'authentication/login_msg.html')

    return render(request, "authentication/signup.html")

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and default_token_generator.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    elif myuser is not None:
        myuser.delete()
        return render(request,'authentication/activation_failed.html')
    
def signin(request):
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]
        user = authenticate(username=email, email= email, password=password)
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

def contact_us(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        message = request.POST.get('message')
        send_mail(
            'Query for NextGen Retail Website',
            f'Email: {email}\n\nMessage: {message}',
            'nextgenretail65@gmail.com',
            ['nextgenretail65@gmail.com'],
            fail_silently=False,
        )
        messages.success(request,"You Query has been submitted.")
        return HttpResponseRedirect(reverse('home'))
    else:
        messages.error(request, "Can't send the mail, please try again!")
        return render(request, 'authentication/index.html')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        user = User.objects.filter(email=email).first()
        if user:
            token = get_random_string(length=32)
            user_token = UserToken.objects.create(email=email, reset_password_token=token)
            current_site = get_current_site(request)
            domain = current_site.domain
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
        return render(request, 'authentication/password_reset_invalid.html')
    if request.method == 'POST':
        new_password = request.POST.get('new_password', '')
        confirm_new_password = request.POST.get('confirm_new_password', '')
        if new_password != confirm_new_password:
            error_message = "Passwords do not match."
            return render(request, 'authentication/reset_password.html', {'error_message': error_message, 'token': token})
        user = User.objects.get(email=user_token.email)
        user.set_password(new_password)
        user.save()

        user_token.delete()
        return render(request, 'authentication/password_reset_complete.html')
    return render(request, 'authentication/reset_password.html', {'token': token})

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity')
            if last_activity:
                timeout_seconds = settings.SESSION_COOKIE_AGE
                if datetime.now() - last_activity > timedelta(seconds=timeout_seconds):
                    logout(request)
                    messages.info(request, 'You have been logged out due to inactivity.')
                    return redirect('signin')

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

        if not user.check_password(old_password):
            messages.error(request, 'Incorrect old password. Please try again.')
            return redirect('change_password')

        if new_password != confirm_new_password:
            messages.error(request, 'New passwords do not match. Please try again.')
            return redirect('change_password')

        user.set_password(new_password)
        user.save()

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

        # Check if there are any changes
        if (
            user.email == new_email
            and user.first_name == first_name
            and user.last_name == last_name
        ):
            messages.info(request, "No changes in details.")
            return redirect('profile_update')

        # Check if new email and confirm email match
        if new_email != confirm_email:
            messages.error(request, "Email addresses do not match.")
            return redirect('profile_update')

        # Check if the new email is already in use
        if new_email != user.email and User.objects.exclude(pk=user.pk).filter(email=new_email).exists():
            messages.error(request, "Email address is already in use.")
            return redirect('profile_update')

        # Update user details
        user.first_name = first_name
        user.last_name = last_name

        if new_email != user.email:
            # Update email address
            user.email = new_email
            # Update username to match new email
            user.username = new_email
            
            user.is_active=False
            # Generate activation token
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            
            # Build activation URL
            domain = get_current_site(request).domain
            activate_url = f"http://{domain}{reverse('activate_email', kwargs={'uidb64': uidb64, 'token': token})}"

            # Send activation email
            subject = 'Activate Your Account'
            message = render_to_string('authentication/activation_email.html', {
                'user': user,
                'activate_url': activate_url,
            })
            user.email_user(subject, message)

            # Save user object to persist changes
            user.save()
            logout(request)
            messages.success(request, 'Email Updated. Please check your email to activate the new address.')

            return render(request, 'authentication/email_change_msg.html')
        else:
            # Save user object if no email update
            user.save()
            messages.success(request, 'Profile updated.')
            return redirect('predict')
    return render(request, "authentication/profile.html")



def activate_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Your email address has been activated successfully.')
        return redirect('signin')
    else:
        messages.error(request, 'Invalid activation link.')
        return render(request,'authentication/activation_failed.html')

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
    if request.method == 'POST':
        chart_data = None
        images_present = False
        
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
                sample_data = pd.read_csv(csv_file)
                
                # Preprocess the data
                sample_data['PurchaseDate'] = pd.to_datetime(sample_data['PurchaseDate'])
                sample_data['Year'] = sample_data['PurchaseDate'].dt.year
                sample_data['Month'] = sample_data['PurchaseDate'].dt.month
                sample_data['Day'] = sample_data['PurchaseDate'].dt.day
                sample_data['Quantity'] = pd.to_numeric(sample_data['Quantity'])
                
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
                # Test the model
                sample_data['PredictedTotalAmount'] = model.predict(sample_data[['Year', 'Month', 'Day', 'Quantity']])

                # Scenario 1: Line graph Plotting the line graph for Predicted TotalAmount & Actual TotalAmount vs PurchaseDate
                sample_data_month = sample_data.groupby(['Year', 'Month']).agg({
                    'PurchaseDate': 'max',
                    'TotalAmount': 'sum',
                    'PredictedTotalAmount': 'sum'
                }).reset_index()

                sample_data_month['PurchaseDate'] = pd.to_datetime(sample_data_month[['Year', 'Month']].assign(DAY=1))
                
                # Prepare chart data for Scenario 5: Line graph for predicted Total Amount vs next 6 months
                last_purchase_date = sample_data['PurchaseDate'].max()
                next_6_months = pd.date_range(start=last_purchase_date, periods=6, freq='M')
                future_data = pd.DataFrame({'Year': next_6_months.year,
                                            'Month': next_6_months.month,
                                            'Day': 1,  # Default to 1 for the day
                                            'Quantity': 1})  # Assume quantity as 1 for prediction
                future_data['PredictedTotalAmount'] = model.predict(future_data[['Year', 'Month', 'Day', 'Quantity']])
                future_data['PurchaseDate'] = next_6_months
                # Prepare chart data
                chart_data = {
                    'labels': sample_data_month['PurchaseDate'].dt.strftime('%Y').tolist(),
                    'predicted_amount': sample_data_month['PredictedTotalAmount'].tolist(),
                    'actual_amount': sample_data_month['TotalAmount'].tolist(),
                    
                    'category_labels': sample_data['Category'].value_counts().index.tolist(),
                    'category_counts': sample_data['Category'].value_counts().tolist(),
                    
                    'top_products': sample_data.groupby('ProductName')['Quantity'].sum().nlargest(10).index.tolist(),
                    'top_products_quantities': sample_data.groupby('ProductName')['Quantity'].sum().nlargest(10).tolist(),

                    'purchase_dates': sample_data_month['PurchaseDate'].dt.strftime('%Y-%m').tolist(),
                    'total_amounts': sample_data_month['TotalAmount'].tolist(),
                    
                    'future_purchase_dates': future_data['PurchaseDate'].dt.strftime('%Y-%m').tolist(),
                    'predicted_total_amounts': future_data['PredictedTotalAmount'].tolist(),
                }
                
                images_present = True
            except Exception as e:
                messages.error(request, f'Error in prediction or data processing: {e}')
                return redirect('predict')
        return render(request, 'dash1.html', {
            
            'form': form,
            'chart_data': json.dumps(chart_data),
            'images_present': images_present,
        })
    elif request.method == "GET":
        form = CSVUploadForm()
        images_present = False
        
        return render(request, 'dash1.html', {
            
            'form': form,
            'images_present': images_present,
        })

@login_required
def download_chart_image(request):
    if request.method == 'POST':
        try:
            chart_data = json.loads(request.body)
            
            # Create a BytesIO buffer to hold the PDF
            buffer = io.BytesIO()

            # Create a new PDF document
            doc = SimpleDocTemplate(buffer, pagesize=letter)

            # List to hold PDF elements
            elements = []

            # Add charts to the PDF
            for chart in chart_data:
                width = chart['width']
                height = chart['height']
                content = chart['content']

                # Create a new Matplotlib figure
                plt.figure(figsize=(width / 100, height / 100))
                plt.text(0.5, 0.5, content, ha='center', va='center')

                # Save the chart to a BytesIO object
                chart_bytes = io.BytesIO()
                plt.savefig(chart_bytes, format='png')
                plt.close()

                # Add the chart image to the PDF
                chart_bytes.seek(0)
                chart_img = Image(chart_bytes)
                elements.append(chart_img)

            # Build the PDF document
            doc.build(elements)

            # Reset the buffer pointer
            buffer.seek(0)

            # Create an HTTP response with the PDF
            response = HttpResponse(buffer, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="charts.pdf"'

            return response
        except Exception as e:
            return HttpResponse(status=500)  # Internal Server Error
    else:
        return HttpResponse(status=405)  # Method Not Allowed
