from ast import Param
import math
from msilib import type_valid
from multiprocessing import context
import re
import secrets
from turtle import Turtle
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User
from graphical_pwd_auth.settings import EMAIL_HOST_PASSWORD, N, TBA, EMAIL_HOST_USER, ALLOWED_HOSTS
from .models import LoginInfo
import random, uuid
from urlparams.redirect import param_redirect
import email
from email.message import EmailMessage
import ssl
import smtplib
from os import urandom
from Crypto.Cipher import AES
import string
import base64

def distance(x_1,y_1,x_2,y_2):
    x_1 = float(x_1)
    y_1 = float(y_1)
    x_2 = float(x_2)
    y_2 = float(y_2)
    euclidean_dis = ((x_1-x_2)**2 + (y_1-y_2)**2)**(1/2)
    d = euclidean_dis*math.exp(euclidean_dis-50)
    return d
    # if (abs(x_1-x_2)> 50 or abs(y_1-y_2)>50):
    #     return True
    # else:
    #     return False


def checkPts(pts, username):
    user = User.objects.get(username=username)
    # send email only id user.logininfo.login_link is not None
    if user.logininfo.pts is None:
        return False
    else:
        epts = user.logininfo.pts
        init_pts= decrypt_pts(epts,username)
        entered= pts.split(' ')
        realval= init_pts.split(' ')
        if len(realval) == len(entered):
            d=0
            for i in range(len(realval)):
                X_1=realval[i].split(',')[0]
                Y_1=realval[i].split(',')[1]

                X_2=entered[i].split(',')[0]
                Y_2=entered[i].split(',')[1]

                d= d+ distance(X_1, Y_1, X_2, Y_2)
            if(d>len(realval)*50):        
                return True
            else:
                return False 
        else:
            return True

def encrypt_pts(pts):
    letters = string.ascii_letters + string.digits + string.punctuation.replace(',','/')
    secret_key = "".join(random.choice(letters) for i in range(16))
    iv= "".join(random.choice(letters) for i in range(16))
    obj = AES.new(secret_key.encode("utf8"), AES.MODE_CFB, iv.encode("utf8"))
    epts = obj.encrypt(pts.encode("utf8"))
    ebs=base64.b64encode(epts).decode()
    sec_key=secret_key+","+iv
    return ebs, sec_key

def decrypt_pts(epts, username):
    user = User.objects.get(username=username)
    # send email only id user.logininfo.login_link is not None
    if user.logininfo.pts is None:
        return False
    else:
        secret_key = user.logininfo.sec_key.split(',')[0]
        iv=user.logininfo.sec_key.split(',')[1]
        obj = AES.new(secret_key.encode('utf-8'), AES.MODE_CFB, iv.encode('utf-8'))
        ebs=base64.b64decode(epts.encode())
        pts = obj.decrypt(ebs).decode()
        return pts

def getType(username):
    user = User.objects.get(username=username)

    return user.logininfo.passtype

def get_pwd_imgs():
    # These images are just to confuse the attacker
    images = random.sample(range(1, 17), N * N)
    print(images)
    p_images = []
    for i in range(0, N * N, N):
        p_images.append(images[i:i+N])
    print(p_images)
    return p_images

def get_pwd_imgs_new():
    # These images are just to confuse the attacker
    images = [i for i in range(1,17)]
    random.shuffle(images)
    print(images)
    p_images = []
    for i in range(0, N * N, N):
        p_images.append(images[i:i+N])
    print(p_images)
    return p_images

def get_imgs_graphical():
    images = [[i] for i in range(0,5)]
    print(images)
    return images

def get_pwd_imgs_story():
    pwd='notany/'
    images = [i for i in range(1,4)]
    pwd_img=[pwd+str(i) for i in images]
    mimg=[['pred/apple/@','pred/home/@','pred/night/@'],['adj/fast/@','adj/good/@','adj/slow/@'],['sub/he/@','sub/it/@','sub/she/@'],['verb/eats/@','verb/sleeps/@','verb/works/@']]
    for i in mimg:
        cnt=0
        for j in i:
            arr=[cnt,cnt+3,cnt+3]
            n=str(random.choice(arr))+'@'
            img=j+str(n)
            pwd_img.append(img)
            cnt+=1
    random.shuffle(pwd_img)
    p_images=[]
    for i in range(0, N*N):
        p_images.append(pwd_img[i:i+1])
    print(p_images)
    return p_images
    




def update_login_info(user, didSuccess):
    if didSuccess:
        user.logininfo.fails = 0
    else:
        user.logininfo.fails += 1
    
    user.logininfo.save()
    print('{} Failed attempts: {}'.format(user.username, user.logininfo.fails))


def isBlocked(username):
    try:
        user = User.objects.get(username=username)
    except Exception:
        return None
    print('isBlocked: {} - {}'.format(user.logininfo, TBA))
    if user.logininfo.fails >= TBA:
        return True
    else:
        return False


def sendLoginLinkMailToUser(username):
    user = User.objects.get(username=username)
    # send email only id user.logininfo.login_link is not None
    if user.logininfo.login_link is None:
        link = str(uuid.uuid4())
        user.logininfo.login_link = link
        user.logininfo.save()
        email_sender = EMAIL_HOST_USER
        email_password= EMAIL_HOST_PASSWORD
        email_reciever= user.email
        subject ='Link to Log in to your account'
        body='''
            Someone tried to bruteforce on your account.
            Click the Link to Login to your account directly.
            The link is one-time clickable
            link: http://{}:8000/login/{}
            '''.format(ALLOWED_HOSTS[-1], link)
        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_reciever
        em['Subject']= subject
        em.set_content(body)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com',587,context=context) as smtp:
            smtp.login(email_sender,email_password)
            smtp.sendmail(email_sender,email_reciever,em.as_string())
        print('LOGIN LINK EMAIL SENT')


def sendPasswordResetLinkToUser(username):
    # send reset link everytime user requests
    try:
        user = User.objects.get(username=username)
    except Exception:
        return False
    
    link = str(uuid.uuid4())
    user.logininfo.reset_link = link
    user.logininfo.save()
    print(link)
    
    email_sender = EMAIL_HOST_USER
    email_password= EMAIL_HOST_PASSWORD
    email_reciever= user.email
    subject ='Link to Log in to your account'
    body='''
        Someone tried to bruteforce on your account.
        Click the Link to Login to your account directly.
        The link is one-time clickable
        link: http://{}:8000/login/{}
        '''.format(ALLOWED_HOSTS[-1], link)
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_reciever
    em['Subject']= subject
    em.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com',587,context=context) as smtp:
        smtp.login(email_sender,email_password)
        smtp.sendmail(email_sender,email_reciever,em.as_string())
    print('PWD RESET LINK EMAIL SENT')
    return True


def home_page(request):
    return render(request, 'home_new.html')

def register_moving(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        print(username, password)
        try:
            # create user and loginInfo for him
            user = User.objects.create_user(email=email, username=username, password=password)
            login_info = LoginInfo(user=user, fails=0, passtype=4)
            login_info.save()
            messages.success(request, 'Account created successfully!')
        except Exception as e:
            print(e)
            messages.warning(request, 'Error while creating Account!')
        
        return redirect(request, 'register_moving.html')
    else:
        data = {
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'register_moving.html', context=data)

def register_page_new(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        print(username, password)
        try:
            # create user and loginInfo for him
            user = User.objects.create_user(email=email, username=username, password=password)
            login_info = LoginInfo(user=user, fails=0, passtype=1)
            login_info.save()
            messages.success(request, 'Account created successfully!')
        except Exception as e:
            print(e)
            messages.warning(request, 'Error while creating Account!')
        
        return redirect('home')
    else:
        data = {
            'p_images': get_pwd_imgs_new(),
        }
        return render(request, 'register_new.html', context=data)

def register_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        print(username, password)
        try:
            # create user and loginInfo for him
            user = User.objects.create_user(email=email, username=username, password=password)
            login_info = LoginInfo(user=user, fails=0, passtype=0)
            login_info.save()
            messages.success(request, 'Account created successfully!')
        except Exception:
            messages.warning(request, 'Error while creating Account!')
        
        return redirect('home')
    else:
        data = {
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'register.html', context=data)

def register_graphical(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        pts = request.POST['points']
        print(username, password,pts)
        try:
            epts, sec_key = encrypt_pts(pts)
            # create user and loginInfo for him
            user = User.objects.create_user(email=email, username=username, password=password)
            login_info = LoginInfo(user=user, fails=0, pts=epts,passtype=2, sec_key=sec_key)
            login_info.save()
            messages.success(request, 'Account created successfully!')
        except Exception as e:
            print(e)
            messages.warning(request, 'Error while creating Account!')
        
        return redirect('home')
    else:
        data = {
            'p_images': get_imgs_graphical(),
        }
        return render(request, 'register_graphical.html', context=data)

def register_story(request):
    if request.method == 'POST':
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            print(username, password, email)
            try:
                # create user and loginInfo for him
                user = User.objects.create_user(email=email, username=username, password=password)
                login_info = LoginInfo(user=user, fails=0,passtype=3)
                login_info.save()
                messages.success(request, 'Account created successfully!')
            except Exception as e:
                print(e)
                messages.warning(request, 'Error while creating Account!')
            
            return render(request, 'register_story.html')
    else:
            return render(request, 'register_story.html')
   
def login_page_story(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_story')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_story')
        else:
            # Not Blocked
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('login_after')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                request.method='GET'
                request.cparam = {'uname': username}
                return param_redirect(request,'login_story')

    else:
        data = {
            'uname': request.GET['uname'],
            'p_images': get_pwd_imgs_story(),
        }
        return render(request, 'login_story.html', context=data)

def login_page_moving(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_moving')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_moving')
        else:
            # Not Blocked
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('login_after')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                request.method='GET'
                request.cparam = {'uname': username}
                return param_redirect(request,'login_moving')

    else:
        data = {
            'uname': request.GET['uname'],
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'login_new.html', context=data)

def login_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login')
        else:
            # Not Blocked
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('login_after')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                request.method='GET'
                request.cparam = {'uname': username}
                return param_redirect(request,'login')

    else:
        data = {
            'uname': request.GET['uname'],
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'login.html', context=data)

def login_page_new(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_new')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_new')
        else:
            # Not Blocked
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('login_after')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                request.method='GET'
                request.cparam = {'uname': username}
                return param_redirect(request,'login_new')

    else:
        data = {
            'uname': request.GET['uname'],
            'p_images': get_pwd_imgs_new(),
        }
        return render(request, 'login_new.html', context=data)

def login_graphical(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        pts = request.POST['points']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_graphical')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            request.method='GET'
            request.cparam = {'uname': username}
            return param_redirect(request,'login_graphical')
        else:
            if checkPts(pts, username):
                messages.warning(request, 'Login Failed!')
                request.method='GET'
                request.cparam = {'uname': username}
                return param_redirect(request,'login_graphical')
            #Not Blocked
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('login_after')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                return redirect('login')

    else:
        data = {
            'uname': request.GET['uname'],
            'p_images': get_imgs_graphical(),
        }
        return render(request, 'login_graphical.html', context=data)


def login_init(request):
    if request.method == 'POST':
        username = request.POST['username']
        print(username)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            return redirect('login_init')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            return redirect('login_init')
        else:
            request.method='GET'
            request.cparam = {'uname': username}
            typ = getType(username)
            if(typ == 0):
                return param_redirect(request,'login')
            

            if(typ == 1):
                return param_redirect(request,'login_new')
            
            if(typ == 2):
                return param_redirect(request,'login_graphical')
            
            return param_redirect(request,'login_story')
            

    else:
        return render(request, 'login_init.html')

def login_from_uid(request, uid):
    try:
        # get user from the uid and reset the Link to 'NO_LINK' again
        login_info = LoginInfo.objects.get(login_link=uid)
        user = login_info.user
        login(request, user)
        update_login_info(user, True)
        login_info.login_link = None
        login_info.save()
        messages.success(request, 'Login successfull!')
    except Exception:
        messages.warning(request, 'Invalid Link. Please check again!')

    return redirect('home')


def reset_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        print(username)
        if sendPasswordResetLinkToUser(username):
            messages.success(request, 'Password Reset Link sent to you email!')
        else:
            messages.warning(request, 'User doesn\'t exist!')
        return redirect('home')
    else:
        return render(request, 'reset_request.html')


def reset_from_uid(request, uid):
    print('hello')
    if request.method == 'POST':
        print('hi-post')
        password = request.POST['password']
        try:
            # get user from the uid and reset the Link to 'NO_LINK' again
            login_info = LoginInfo.objects.get(reset_link=uid)
            user = login_info.user
            # reset pwd
            user.set_password(password)
            login_info.reset_link = None
            login_info.save()
            user.save()
            messages.success(request, 'Password Changed Successfully!')
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
        return redirect('home')
    else:
        print('hi-else')
        try:
            # To make sure the link is valid
            print(uid)
            login_info = LoginInfo.objects.get(reset_link=uid)
            data = {
                'p_images': get_pwd_imgs(),
            }
            return render(request, 'reset.html', context=data)
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
            return redirect('home')


def logout_page(request):
    logout(request)
    messages.warning(request, 'You\'ve been logged out!')
    return redirect('home')

def login_after(request):
    return render(request, 'login_after.html')
