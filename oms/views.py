# -*- coding: utf-8 -*-
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib import auth
from django.contrib.auth.decorators import login_required
import utils
from django.contrib.auth.decorators import login_required
from django.shortcuts import render,HttpResponse,HttpResponseRedirect

@login_required()
def index(request):
    return render_to_response('index.html')

def acc_login(request):
    if request.method == "POST":

        username = request.POST.get('email')
        password = request.POST.get('password')
        user = auth.authenticate(username=username,password=password)
        if user is not None:

            if django.utils.timezone.now() > user.valid_begin_time and django.utils.timezone.now()  < user.valid_end_time:
                auth.login(request,user)
                request.session.set_expiry(60*30)
                #print 'session expires at :',request.session.get_expiry_date()
                return HttpResponseRedirect('/')
            else:
                return render(request,'login.html',{'login_err': 'User account is expired,please contact your IT guy for this!'})

        else:
            return render(request,'login.html',{'login_err': 'Wrong username or password!'})
    else:
        return render(request, 'login.html')

