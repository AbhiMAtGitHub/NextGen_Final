import base64
import io
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
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
import matplotlib.pyplot as plt
import joblib
import os
import json
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

# @login_required
# def profile_update(request):
#     if request.method == "POST":
#         user = request.user
        
#         new_email = request.POST["new_email"]
#         confirm_email = request.POST["confirm_email"]
#         first_name = request.POST["first_name"]
#         last_name = request.POST["last_name"]

#         if (
#             user.email == new_email
#             and user.first_name == first_name
#             and user.last_name == last_name
#         ):
#             messages.info(request, "No changes in details.")
#             return redirect('profile_update')

#         if new_email != confirm_email:
#             messages.error(request, "Email addresses do not match.")
#             return redirect('profile_update')

#         if new_email != user.email and User.objects.exclude(pk=user.pk).filter(email=new_email).exists():
#             messages.error(request, "Email address is already in use.")
#             return redirect('profile_update')

#         user.first_name = first_name
#         user.last_name = last_name

#         if new_email != user.email:
#             user.username = new_email
#             user.email = new_email
#             user.is_active = False

#             current_site = get_current_site(request)
#             from_email = settings.DEFAULT_FROM_EMAIL
#             to_list = [user.email]
#             mail_subject = 'Activate your account'
#             message = render_to_string('authentication/email_confirmation.html', {
#                 'user': user,
#                 'domain': current_site.domain,
#                 'uid': urlsafe_base64_encode(force_bytes(user.pk)),
#                 'token': generate_token.make_token(user),
#             })

#             send_mail(mail_subject, message, from_email, to_list, fail_silently=True)

#             logout(request)
#             messages.success(request, 'An activation link has been sent to your new email address. Please check your email to activate your account.')
            
#             return render(request, 'authentication/email_change_msg.html')
#         else:
#             user.save()
#             messages.success(request, 'Profile updated.')
#             return redirect('predict')

#     return render(request, "authentication/profile.html")


@login_required
def profile_update(request):
    if request.method == "POST":
        user = request.user
        new_email = request.POST.get("new_email")
        confirm_email = request.POST.get("confirm_email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")

        if new_email != user.email:
            if new_email != confirm_email:
                messages.error(request, "Email addresses do not match.")
                return redirect('profile_update')

            user.email = new_email
            user.is_active = False
            user.save()

            current_site = get_current_site(request)
            mail_subject = 'Activate your account'
            message = render_to_string('activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user),
            })
            send_mail(mail_subject, message, None, [new_email])

            messages.success(request, 'An activation link has been sent to your new email address. Please check your email to activate your account.')
            return redirect('profile_update')
        else:
            user.first_name = first_name
            user.last_name = last_name
            user.save()
            messages.success(request, 'Profile updated.')
            return redirect('profile_update')
    else:
        return render(request, "authentication/profile.html")

def activate_profile(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'authentication/email_change_msg.html')
    else:
        return render(request, 'authentication/activation_failed.html')
    
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

# @login_required
# def prediction(request):
#     if request.method == 'POST':
#         predicted_amount_plot = None
#         pie_chart = None
#         bar_graph = None
#         line_graph = None
#         revenue_prediction_graph = None
#         images_present = False
#         user_first_name = request.user.first_name if request.user.first_name else ""
        
#         form = CSVUploadForm(request.POST, request.FILES)
#         if form.is_valid():
#             csv_file = request.FILES['csv_file']
            
#             if not csv_file:
#                 messages.error(request, "No file uploaded.")
#                 return redirect('predict')
           
#             if not csv_file.name.endswith('.csv'):
#                 messages.error(request, "Please upload a CSV file.")
#                 return redirect('predict')
 
#             try:
#                 sample_data = pd.read_csv(csv_file)
                
#                 # Preprocess the data
#                 sample_data['PurchaseDate'] = pd.to_datetime(sample_data['PurchaseDate'])
#                 sample_data['Year'] = sample_data['PurchaseDate'].dt.year
#                 sample_data['Month'] = sample_data['PurchaseDate'].dt.month
#                 sample_data['Day'] = sample_data['PurchaseDate'].dt.day
#                 sample_data['Quantity'] = pd.to_numeric(sample_data['Quantity'])
                
#             except Exception as e:
#                 messages.error(request, f'Error reading CSV: {e}')
#                 return redirect('predict')
                           
#             model_path = settings.ML_MODEL_PATH
 
#             if not os.path.exists(model_path):
#                 messages.error(request, "Model file not found.")
#                 return redirect('predict')
                 
#             try:
#                 model = joblib.load(model_path)
#             except Exception as e:
#                 messages.error(request, f'Error loading model: {e}')
#                 return redirect('predict')
             
#             try:
#                 # Test the model
#                 sample_data['PredictedTotalAmount'] = model.predict(sample_data[['Year', 'Month', 'Day', 'Quantity']])

#                 # Scenario 1: Line graph Plotting the line graph for Predicted TotalAmount & Actual TotalAmount vs PurchaseDate
#                 sample_data_month = sample_data.groupby(['Year', 'Month']).agg({
#                     'PurchaseDate': 'max',
#                     'TotalAmount': 'sum',
#                     'PredictedTotalAmount': 'sum'
#                 }).reset_index()

#                 sample_data_month['PurchaseDate'] = pd.to_datetime(sample_data_month[['Year', 'Month']].assign(DAY=1))
#                 plt.figure(figsize=(10, 6))
#                 plt.plot(sample_data_month['PurchaseDate'], sample_data_month['PredictedTotalAmount'], marker='o', label='Predicted TotalAmount')
#                 plt.plot(sample_data_month['PurchaseDate'], sample_data_month['TotalAmount'], marker='o', label='Actual TotalAmount')
#                 plt.title('Monthly TotalAmount')
#                 plt.xlabel('Date')
#                 plt.ylabel('TotalAmount')
#                 plt.legend()
#                 plt.grid(True)
#                 plt.xticks(rotation=45)
#                 plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y'))
#                 plt.gca().xaxis.set_major_locator(plt.matplotlib.dates.YearLocator())
#                 plt.tight_layout()
#                 plt.subplots_adjust(bottom=0.15)
#                 # Convert the plot to base64 format
#                 buffer = io.BytesIO()
#                 plt.savefig(buffer, format='png')
#                 buffer.seek(0)
#                 predicted_amount_plot = base64.b64encode(buffer.getvalue()).decode('utf-8')
#                 buffer.close()
#                 plt.close()

#                 # Scenario 2: Pie chart of Category Distribution
#                 plt.figure(figsize=(8, 8))
#                 plt.pie(sample_data['Category'].value_counts(), labels=sample_data['Category'].value_counts().index, autopct='%1.1f%%')
#                 plt.title('Category Distribution')
#                 buffer = io.BytesIO()
#                 plt.savefig(buffer, format='png')
#                 buffer.seek(0)
#                 pie_chart = base64.b64encode(buffer.getvalue()).decode('utf-8')
#                 buffer.close()
#                 plt.close()
                
#                 # Scenario 3: Bar chart for Top 10 Products by Quantity Sold
#                 top_10_products = sample_data.groupby('ProductName')['Quantity'].sum().nlargest(10)
#                 plt.figure(figsize=(10, 6))
#                 top_10_products.plot(kind='bar')
#                 plt.title('Top 10 Products by Quantity Sold')
#                 plt.xlabel('Product Name')
#                 plt.ylabel('Quantity Sold')
#                 plt.xticks(rotation=45)
#                 buffer = io.BytesIO()
#                 plt.savefig(buffer, format='png')
#                 buffer.seek(0)
#                 bar_graph = base64.b64encode(buffer.getvalue()).decode('utf-8')
#                 buffer.close()
#                 plt.close()
 
#                 # Scenario 4: Line graph for TotalAmount Over PurchaseDate
#                 plt.figure(figsize=(10, 6))
#                 plt.plot(sample_data_month['PurchaseDate'], sample_data_month['TotalAmount'], marker='o')
#                 plt.title('Monthly TotalAmount')
#                 plt.xlabel('Date')
#                 plt.ylabel('TotalAmount')
#                 plt.grid(True)
#                 plt.xticks(rotation=45)
#                 plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y'))
#                 plt.gca().xaxis.set_major_locator(plt.matplotlib.dates.YearLocator())
#                 plt.tight_layout()
#                 plt.subplots_adjust(bottom=0.15)
#                 buffer = io.BytesIO()
#                 plt.savefig(buffer, format='png')
#                 buffer.seek(0)
#                 line_graph = base64.b64encode(buffer.getvalue()).decode('utf-8')
#                 buffer.close()
#                 plt.close()
 
#                 # Scenario 5: Line graph for predicted TotalAmount vs next 6 months
#                 last_purchase_date = sample_data['PurchaseDate'].max()
#                 next_6_months = pd.date_range(start=last_purchase_date, periods=6, freq='M')
#                 future_data = pd.DataFrame({'Year': next_6_months.year,
#                                             'Month': next_6_months.month,
#                                             'Day': 1,  # Default to 1 for the day
#                                             'Quantity': 1})  # Assume quantity as 1 for prediction
#                 future_data['PredictedTotalAmount'] = model.predict(future_data[['Year', 'Month', 'Day', 'Quantity']])
#                 future_data['PurchaseDate'] = next_6_months
#                 # Plot the graph
#                 plt.figure(figsize=(10, 6))
#                 plt.plot(future_data['PurchaseDate'], future_data['PredictedTotalAmount'], marker='o')
#                 plt.title('Predicted TotalAmount for Next 6 Months')
#                 plt.xlabel('Date')
#                 plt.ylabel('Predicted TotalAmount')
#                 plt.grid(True)
#                 plt.xticks(rotation=45)
#                 plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y-%m'))
#                 plt.gca().xaxis.set_major_locator(plt.matplotlib.dates.MonthLocator())
#                 plt.tight_layout()
#                 plt.subplots_adjust(bottom=0.15)
#                 buffer = io.BytesIO()
#                 plt.savefig(buffer, format='png')
#                 buffer.seek(0)
#                 revenue_prediction_graph = base64.b64encode(buffer.getvalue()).decode('utf-8')
#                 buffer.close()
#                 plt.close()
               
#                 images_present = True
#             except Exception as e:
#                 messages.error(request, f'Error in prediction or data processing: {e}')
#                 return redirect('predict')
#         return render(request, 'authentication/dashboard.html', {
#             'user_first_name': user_first_name,
#             'form': form,
#             'pie_chart': pie_chart,
#             'bar_graph': bar_graph,
#             'line_graph': line_graph,
#             'predicted_amount_plot': predicted_amount_plot,
#             'revenue_prediction_graph': revenue_prediction_graph,
#             'images_present': images_present,
#         })
#     elif request.method == "GET":
#         form = CSVUploadForm()
#         predicted_amount_plot = None
#         pie_chart = None
#         bar_graph = None
#         line_graph = None
#         revenue_prediction_graph = None
#         images_present = False
#         user_first_name = request.user.first_name if request.user.first_name else ""
        
#         return render(request, 'authentication/dashboard.html', {
#             'user_first_name': user_first_name,
#             'form': form,
#             'pie_chart': pie_chart,
#             'bar_graph': bar_graph,
#             'line_graph': line_graph,
#             'predicted_amount_plot': predicted_amount_plot,
#             'revenue_prediction_graph': revenue_prediction_graph,
#             'images_present': images_present,
#         })

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

import matplotlib
matplotlib.use('Agg')  # Use Agg backend instead of the default GUI backend

from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Image
import matplotlib.pyplot as plt
import io
import json

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
