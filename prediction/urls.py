from django.urls import path
from . import views
urlpatterns = [
    path('', views.home, name = 'home'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('signup',views.signup, name='signup'),
    path('signin',views.signin, name='signin'),
    path('predict',views.prediction, name='predict'),
    path('signout',views.signout, name='signout'),
    path('contact_us',views.contact_us, name='contact_us'), 
    path('delete_user',views.delete_user, name='delete_user'), 
    path('forgot_password',views.forgot_password, name='forgot_password'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('change_password', views.change_password, name='change_password'),
    path('profile_update', views.profile_update, name='profile_update'),
    path('download_chart_image', views.download_chart_image, name='download_chart_image'),
    path('activate/<uidb64>/<token>/', views.activate_email, name='activate_email'),
]
