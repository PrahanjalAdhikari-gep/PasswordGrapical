from django.urls import path, include
from .views import (
    home_page, 
    register_page, 
    login_page, 
    logout_page, 
    login_from_uid, 
    reset_view, 
    reset_from_uid,
    register_page_new,
    login_page_new,
    register_graphical,
    login_graphical,
    login_init,
    )

urlpatterns = [
    path('', home_page, name='home'),
    path('register/', register_page, name='register'),
    path('register_new/', register_page_new, name='register_new'),
    path('register_graphical/', register_graphical, name='register_graphical'),
    path('login_graphical/',login_graphical,name='login_graphical'),
    path('login_init/',login_init,name='login_init'),
    path('login/', login_page, name='login'),
    path('login_new/', login_page_new, name='login_new'),
    path('login/<str:uid>', login_from_uid, name='login_uid'),
    path('logout/', logout_page, name='logout'),
    path('reset/', reset_view, name='reset'),
    path('reset/<str:uid>', reset_from_uid, name='reset_uid'),
]
