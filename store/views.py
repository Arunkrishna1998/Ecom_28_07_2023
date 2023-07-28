import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from django.utils import timezone
import requests


def index(request):
    product_list = Products.objects.all().filter(is_deleted=False,in_store=True)[:12]
    image = ProductImage.objects.all()
    context = {'product_list':product_list,'image':image}
    return render(request, 'store/home.html', context)


def product_details(request, product_id):
    product = Products.objects.get(uid=product_id)
    colors = ColorVariant.objects.filter(product_id=product_id)
    image_list = ProductImage.objects.all().filter(product=product)
    context = {'product':product,'colors':colors,'image_list':image_list}
    return render(request, 'store/product_details.html', context)


def size_list(request):
    print("*************Calling Size*************")
    color_id = request.GET['color_id']
    size_list = SizeVariant.objects.filter(Color_id=color_id)
    context = {'size_list':size_list}
    return render(request, 'store/more/size_list.html', context)


def show_price(request):
    size_id = request.GET['size_id']
    size = SizeVariant.objects.get(uid=size_id)
    context = {'price':size.price}
    return render(request, 'store/more/show_price.html', context)







#############################USER##########################################3

# from .forms import UserRegistrationForm
import random

from django.contrib.auth.models import User
from . models import Customer
def register(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        contact = request.POST['contact']

        password = str(random.randint(111111, 999999))
        user = User.objects.create_user(username=email,email=email,first_name=first_name,last_name=last_name,password=password)
        user.is_active = True
        user.save()
        Customer(user=user, email=user.email,contact=contact,otp=password).save()
        activateEmail(request, user, user.email, password)
        remaining_time = 120
        return render(request, 'user/signin.html', context={"username":user.email,'remaining_time': remaining_time})
    else:
        return render(request, 'user/register.html')


def category_list(request):
    category_list = Category.objects.all()
    context = {'category_list':category_list}
    return render(request, 'store/more/category_list.html', context)


from django.utils import timezone
from datetime import timedelta
def activateEmail(request, user, to_email,otp):
    mail_subject = "Login to your user account Using this OTP."
    message = render_to_string("mailbody/email_template.html", {
        'user': f'{user.first_name} {user.last_name}',
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': f'Your One Time Password is {otp}',
        "protocol": 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        pass
        # messages.success(request, f'Dear {user}, please go to you email {to_email} and check for the OTP \
        #         Note: Check your spam folder.')
    else:
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')


def validateOTP(request):
    if request.method == 'POST':
        otp = str(request.POST['otp'])
        email = request.POST['email']
        try:
            u_obj = User.objects.get(email=email)
            if u_obj.password == otp:
                print("***************u_obj.password == otp***************")
                u = User.objects.get(email=email)
                u.is_active = True
                u.save()
                username = u_obj.username
                user = authenticate(request, username=username, password=otp)
                if user is not None:
                    login(request, user)
                    print("***************************")
                    return redirect('index')

            return redirect('signin')
        except Customer.DoesNotExist:
            print("Didnotwork*********************************")

            return render(request, 'user/validateOTP.html', context={'email':email, 'msg':'Wrong OTP Try Again!'})


    return render(request, 'user/validateOTP.html')


from django.contrib.auth import login, logout, authenticate, get_user_model
from . forms import UserLogin,AdminLogin
def signin(request):
    if request.method == 'POST':
        email = request.POST['username']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            password = str(random.randint(111111, 999999))
            user.set_password(password)
            user.save()
            print("*************************",password)
            activateEmail(request, user, user.email, password)
            messages.info(request,'OTP is Send To Your Email. Please Check')
            remaining_time = 120
            # otp_expiration_time = timezone.now() + timedelta(minutes=2)
            context = {'remaining_time': remaining_time,'username':email}
            return render(request, 'user/signin.html', context)
    else:
        return render(request, 'user/signin.html')




# def signin_confirmation(request):
# 	if request.method == 'POST':
# 		username = request.POST['username']
# 		password = str(request.POST['password'])
# 		print(username,password)
# 		user = authenticate(request, username=username, password=password)
# 		if user is not None:
# 			try:
# 				cart = uCart.objects.get(cart_id=_cart_id(request))
# 				is_cart_item = CartItems.objects.filter(cart=cart).exists()
# 				if is_cart_item:
# 					cart_items = CartItems.objects.filter(cart=cart)
#
# 					for item in cart_items:
# 						item.user = user
# 						item.save()
#
# 			except:
# 				pass
# 			login(request, user)
# 			return redirect('index')
# 		else:
# 			messages.error(request, 'Invalid username or password')
# 			context = {'username':username}
# 			return render(request, 'user/signin.html', context)
# 	else:
# 		return render(request, 'user/signin.html')


# def signin_confirmation(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = str(request.POST['password'])
#         print(username, password)
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             try:
#                 cart = uCart.objects.get(cart_id=_cart_id(request))
#                 is_cart_item = CartItems.objects.filter(cart=cart).exists()
#                 if is_cart_item:
#                     cart_items = CartItems.objects.filter(cart=cart)
#
#                     for item in cart_items:
#                         item.user = user
#                         item.save()
#
#             except:
#                 pass
#             login(request, user)
#             return redirect('index')
#
#     else:
#         otp_expiration_time = timezone.now() + timedelta(minutes=2)
#     context = {'otp_expiration_time': otp_expiration_time}
#
#     # context = {'remaining_time': remaining_time}
#     return render(request, 'user/signin.html', context)


from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages


def signin_confirmation(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = str(request.POST['password'])
        remaining_time = request.POST['remaining_time']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            try:
                cart = uCart.objects.get(cart_id=_cart_id(request))
                is_cart_item = CartItems.objects.filter(cart=cart).exists()
                if is_cart_item:
                    cart_items = CartItems.objects.filter(cart=cart)

                    for item in cart_items:
                        item.user = user
                        item.save()

            except:
                pass
            login(request, user)
            return redirect('index')
        else:
            messages.error(request, 'Invalid username or password')
            context = {'username': username,'remaining_time':remaining_time}
            return render(request, 'user/signin.html', context)


def customer_logout(request):
    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("index")


def search_product(request, category=None):
    if request.method=='POST':
        query=request.POST['query']
        product_list = Products.objects.all().filter(is_deleted=False, in_store=True, slug__contains=query).order_by('uid')
        category_list = Category.objects.all()
        paginator = Paginator(product_list, 3)
        page = request.GET.get('page')
        paged_product = paginator.get_page(page)
        context = {'product_list': paged_product, 'category_list': category_list}
        return render(request, 'store/store.html', context)
    else:
        product_list = Products.objects.all().filter(in_store=True).order_by('uid')
        category_list = Category.objects.all()
        paginator = Paginator(product_list, 3)
        page = request.GET.get('page')
        paged_product = paginator.get_page(page)
        context = {'product_list': paged_product, 'category_list': category_list}
        return render(request, 'store/store.html', context)


from django.db.models import Q
def search_product_price(request):
    if request.method == 'POST':
        minValue = int(request.POST['minValue'])
        maxValue = int(request.POST['maxValue'])
        cartItems = 0
        print(minValue,maxValue)
        if minValue <= 0 & maxValue != 0:
            products = Products.objects.filter(price__lte=maxValue)
        elif maxValue <= 0 & minValue != 0:
            products = Products.objects.filter(price__gte=minValue)
        elif minValue >= 0 & maxValue >= 0:
            q_obj = Q(price__gte=minValue) & Q(price__lte=maxValue)
            products = Products.objects.filter(q_obj)
        elif minValue <= 0 & maxValue <= 0:
            q_obj = Q(price__gte=minValue) & Q(price__lte=maxValue)
            products = Products.objects.filter(q_obj)
        else:
            q_obj = Q(price__gte=minValue) | Q(price__lte=maxValue)
            products = Products.objects.filter(q_obj)


        # products = Products.objects.filter(price__contains=query)
        context = {'products': products, 'cartItems': cartItems}
        return render(request, 'store/store.html', context)
########################################ADMIN##################################################################
from django.views.decorators.cache import cache_control
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_login(request):
    if request.method == 'POST':
        form = AdminLogin(request,request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            print(username,password)
            user = authenticate(request, username=username, password=password)
            if user is not None and user.is_staff == True:
                login(request, user)
                return redirect('admin_home')
            else:
                form.add_error(None, 'Invalid username or password')
        else:
                messages.error(request, 'Invalid username or password')
    else:
        form = AdminLogin()
    return render(request, 'admin_main/admin_login.html', {'form': form})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_home(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return render(request, 'admin_main/admin_base.html')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_logout(request):
    if request.user.is_authenticated and request.user.is_superuser:
        logout(request)
        messages.info(request, "Logged out successfully!")
        return redirect("admin_login")

def admin_change_password(request):
    if request.method == 'POST':
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        email = request.POST['email']
        if password1 == password2:
            user = User.objects.get(email=email)
            user.set_password(password1)
            user.save()
            return redirect('admin_login')
        else:
            messages.error(request, "Passwords Does not match")

    email = request.GET.get('email')
    token = request.GET.get('token')
    print(email,token)
    try:
        user = User.objects.get(username=email)
    except User.DoesNotExist:
        user = None

    token_generator = PasswordResetTokenGenerator()
    token_valid = user is not None and token_generator.check_token(user, token)

    if user and token_valid:
        context = {
            'email': email,
            'token': token,
        }
        return render(request, 'admin_main/forgot_password/forgot_password.html', context)
    else:
        return render('index')



from django.contrib.auth.tokens import PasswordResetTokenGenerator
def passwordChangeEmail(request, user, to_email, token):
    token_generator = PasswordResetTokenGenerator()
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = token_generator.make_token(user)

    mail_subject = "Click On the link to Set new Password"
    message = render_to_string("admin_main/forgot_password/password_email.html", {
        'domain': get_current_site(request).domain,
        'uid': uid,
        'token': token,
        "protocol": 'https' if request.is_secure() else 'http',
        'email':user.email,
        'reset_link' : f"{request.scheme}://{request.get_host()}/admin_change_password/?email={user.email}&token={token}",
        'scheme':request.scheme,
        'host':request.get_host(),
    })

    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        request.session['otp_sent_timestamp'] = timezone.now().timestamp()
        # messages.success(request, f'Dear {user}, please go to your email {to_email} and check for the OTP. Note: Check your spam folder.')
    else:
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')

def get_link(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            passwordChangeEmail(request, user, user.email,user.password)
            messages.success(request, 'Check Your Email For Password Reset Link')
        except User.DoesNotExist:
            messages.error(request, 'Make Sure you enter a valid email')

    return render(request, 'admin_main/forgot_password/get_link.html')






#@login_required('admin_login')
def admin_user_details_view(request):
    users_list = User.objects.exclude(is_staff=True)
    context = {'users_list':users_list}
    return render(request, 'admin_main/admin_user_details_view.html', context)

#@login_required('admin_login')
def admin_block_unblock(request):
    id = request.GET['id']
    user = User.objects.get(id=id)
    if user.is_active:
        user.is_active = False
        user.save()
        messages.info(request, "User Account Blocked")
    else:
        user.is_active = True
        user.save()
        messages.info(request, "User Account Unblocked")
    users_list = User.objects.exclude(is_staff=True)
    context = {'users_list':users_list}
    return render(request, 'admin_main/admin_user_details_view.html', context)

from . models import Category
from django.utils.text import slugify
#@login_required('admin_login')
def admin_categories_add(request):
    if request.method == 'POST':
        try:
            category = request.POST['category']
            # messages.error(request, "Category is Already in ")
            c = Category(category_name=category, slug=slugify(category))
            c.save()
            messages.info(request,"New Category added")
        except:
            messages.warning(request, "This Category may already exist")
        return redirect('categories')
    return render(request, 'admin_main/categories.html')

#@login_required('admin_login')
def categories(request):
    category_list = Category.objects.all()
    context = {'category_list':category_list}
    return render(request, 'admin_main/categories.html', context)

#@login_required('admin_login')
def admin_categories_edit(request):
    if request.method == 'POST':
        category = request.POST['category']
        id = request.POST['id']
        ctg = Category.objects.get(uid=id)
        ctg.category_name=category
        ctg.slug=slugify(category)
        ctg.save()
        return redirect('categories')
    else:
        id = request.GET['id']
        ctg = Category.objects.get(uid=id)
        edit = True
        category_list = Category.objects.all()
        context = {'ctg': ctg, 'edit':edit,'category_list':category_list}
        return render(request, 'admin_main/categories.html', context)

#@login_required('admin_login')
def admin_categories_delete(request):
    id = request.GET['id']
    ctg = Category.objects.get(uid=id)
    if ctg.is_deleted == True:
        ctg.is_deleted = False
        ctg.save()
        messages.success(request, "Unblocked successfully!")
        return redirect('categories')
    ctg.is_deleted = True
    ctg.save()
    messages.error(request, "Deleted successfully!")
    return redirect('categories')

#@login_required('admin_login')
def admin_products_view(request):
    products = Products.objects.all()
    context = {'products_list': products}
    return render(request, 'admin_main/product_lists.html', context)

#@login_required('admin_login')
def delete_product(request):
    product_id = request.GET['id']
    product = Products.objects.get(uid=product_id)
    product.is_deleted = True
    product.delete()
    return redirect('admin_products_view')


def admin_product_edit(request):
    pass



from .models import Category, ColorVariant, SizeVariant, Products, ProductImage
from django.conf import settings
import os
from django.core.files.storage import FileSystemStorage

#@login_required('admin_login')
def admin_product_add(request):
    if request.method == 'POST':
        try:
            product_name = request.POST.get('productname')
            product_price = request.POST.get('productprice')
            category_id = request.POST.get('category')
            image = request.FILES['image']
            product_description = request.POST.get('product_description')

            category = None
            if category_id:
                category = Category.objects.get(uid=category_id)


            product = Products.objects.create(
                product_name=product_name,
                price=product_price,
                category=category,
                product_description=product_description,
            )

            file_name = image.name
            file_path = os.path.join(settings.MEDIA_ROOT, file_name)
            with open(file_path, 'wb') as file:
                file.write(image.read())

            product.image = file_name
            product.save()

            messages.success(request, "Product Added To Store")

            return redirect('admin_product_add')
        except:
            messages.error(request, "Couldn't Add Product To Store")

            return redirect('admin_product_add')


    categories = Category.objects.all()
    return render(request, 'admin_main/admin_product_add.html', {'category_list': categories})


#@login_required('admin_login')
def admin_product_details_update(request):
    if request.method == 'POST':
        product_id = request.POST['id']
        product_name = request.POST['productname']
        price = request.POST['productprice']
        product_description = request.POST['product_description']
        category_id = request.POST['category']
        product = Products.objects.get(uid=product_id)
        category = Category.objects.get(uid=category_id)

        product.product_name=product_name
        product.price=price
        product.product_description=product_description
        product.category=category
        product.save()
        messages.success(request, 'Details Updated')

        categories = Category.objects.all().filter(is_deleted=False)
        context = {'category_list': categories, 'product': product}
        return render(request, 'admin_main/admin_product_details_update.html', context)

    product_id = request.GET['id']
    product = Products.objects.get(uid=product_id)
    categories = Category.objects.all().filter(is_deleted=False)
    context = {'category_list': categories,'product':product}
    return render(request, 'admin_main/admin_product_details_update.html', context)

#@login_required('admin_login')
def product_variants_view(request):
    product_id = request.GET['id']
    if product_id:
        product = Products.objects.get(uid=product_id)

    size_list = SizeVariant.objects.all()
    color_list = ColorVariant.objects.filter(product_id=product)
    context = {'product_id': product_id, 'color_list': color_list,'size_list':size_list}
    return render(request, 'admin_main/product_variants_view.html', context)

#@login_required('admin_login')
def product_variants_add(request):
    if request.method == 'POST':
        product_id = request.POST['product_id']
        color = request.POST['color']
        size_l = request.POST.getlist('size[]')
        price_l = request.POST.getlist('price[]')
        stock_l = request.POST.getlist('stock[]')
        if product_id:
            product = Products.objects.get(uid=product_id)



        if ColorVariant.objects.filter(product_id=product,color=color).exists():
            color_id = ColorVariant.objects.get(product_id=product, color=color)
            for i in range(len(size_l)):
                if int(stock_l[i])>=0 and int(price_l[i])>0:
                    SizeVariant.objects.create(product_id=product,
                                               Color_id=color_id,
                                               size=size_l[i], price=price_l[i], stock=stock_l[i])
                else:
                    messages.info(request, "Couldn't update! Check if stock or price is valid")
                    size_list = SizeVariant.objects.all()
                    color_list = ColorVariant.objects.filter(product_id=product)
                    context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list}
                    return render(request, 'admin_main/product_variants_view.html', context)
        else:
            color_id = ColorVariant.objects.create(product_id=product,color=color)
            for i in range(len(size_l)):
                if int(stock_l[i]) >= 0 and int(price_l[i]) > 0:
                    SizeVariant.objects.create(product_id=product,
                                               Color_id=color_id,
                                               size=size_l[i],price=price_l[i],stock=stock_l[i])
                else:
                    messages.info(request, "Couldn't update! Check if stock or price is valid")
                    size_list = SizeVariant.objects.all()
                    color_list = ColorVariant.objects.filter(product_id=product)
                    context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list}
                    return render(request, 'admin_main/product_variants_view.html', context)


        size_list = SizeVariant.objects.all()
        color_list = ColorVariant.objects.filter(product_id=product)
        context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list}
        return render(request, 'admin_main/product_variants_view.html', context)

    else:
        product_id = request.GET['id']
        if product_id:
            product = Products.objects.get(uid=product_id)

        size_list = SizeVariant.objects.all()
        color_list = ColorVariant.objects.filter(product_id=product)
        context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list}
        return render(request, 'admin_main/product_variants_view.html', context)

#@login_required('admin_login')
def product_variants_stock_update(request,size_id,product_id):
    if product_id:
        product = Products.objects.get(uid=product_id)
    size_list = SizeVariant.objects.all()
    color_list = ColorVariant.objects.filter(product_id=product)
    if size_id:
        size = SizeVariant.objects.get(uid=size_id)
    update = True
    context = {'product_id': product_id,
               'color_list': color_list,
               'size_list': size_list,
               'size':size,
               'update':update}
    return render(request, 'admin_main/product_variants_view.html', context)


def product_variants_stock_updates(request):
    if request.method == 'POST':
        product_id = request.POST['product_id']
        size_id = request.POST['size_id']
        price = request.POST['price']
        size = request.POST['size']
        stock = request.POST['stock']
        s = SizeVariant.objects.get(uid=size_id)
        s.price=price
        s.stock=stock
        s.size=size
        s.save()

        messages.success(request,'Details Updated')
        product = Products.objects.get(uid=product_id)
        color_list = ColorVariant.objects.filter(product_id=product)
        size_list = SizeVariant.objects.all()
        update = False
        context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list, 'size': size, 'update': update}
        return render(request, 'admin_main/product_variants_view.html', context)

#@login_required('admin_login')
def variants_stock_update_cancel(request, product_id):
    if product_id:
        product = Products.objects.get(uid=product_id)

    size_list = SizeVariant.objects.all()
    color_list = ColorVariant.objects.filter(product_id=product)
    context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list}
    return render(request, 'admin_main/product_variants_view.html', context)

    size_list = SizeVariant.objects.all()
    color_list = ColorVariant.objects.filter(product_id=product)
    context = {'product_id': product_id, 'color_list': color_list, 'size_list': size_list}
    return render(request, 'admin_main/product_variants_view.html', context)

#@login_required('admin_login')
def product_variant_images(request,color):
    image_list = ProductImage.objects.filter(Color_id = color)
    context = {'image_list': image_list,'color':color}
    return render(request, 'admin_main/product_variant_images.html', context)

#@login_required('admin_login')
# def product_variant_images_add(request):
# 	if request.method == 'POST':
# 		color_id = request.POST['color']
# 		product_images = request.FILES.getlist('image_list[]')
# 		color = ColorVariant.objects.get(uid=color_id)
#
# 		for image in product_images:
# 			product_image = ProductImage(product=color.product_id,Color_id=color)
# 			file_name = image.name
# 			file_path = os.path.join(settings.MEDIA_ROOT, file_name)
# 			with open(file_path, 'wb') as file:
# 				file.write(image.read())
#
# 			product_image.image = file_name
# 			product_image.save()
#
# 		image_list = ProductImage.objects.filter(Color_id=color_id)
# 		context = {'image_list': image_list, 'color': color_id}
# 		return render(request, 'admin_main/product_variant_images.html', context)

import os
from PIL import Image
from django.conf import settings
from django.core.files.storage import default_storage
from django.http import JsonResponse, HttpResponseBadRequest
# from django.shortcuts import render
# from .models import ProductImage, ColorVariant


def resize_image(image_file_path):
    img = Image.open(image_file_path)
    fixed_width = 100
    fixed_height = 100
    resized_img = img.resize((fixed_width, fixed_height), Image.ANTIALIAS)
    resized_img.save(image_file_path)



# def product_variant_images_add(request):
#     if request.method == 'POST':
#         color_id = request.POST.get('color')
#         product_images = request.FILES.getlist('image_list[]')
#
#         try:
#             color = ColorVariant.objects.get(uid=color_id)
#
#             for image in product_images:
#                 product_image = ProductImage(product=color.product_id, Color_id=color)
#                 file_name = image.name
#                 file_path = os.path.join(settings.MEDIA_ROOT, file_name)
#                 with open(file_path, 'wb') as file:
#                     file.write(image.read())
#
#                 product_image.image = file_name
#                 product_image.save()
#
#             image_list = ProductImage.objects.filter(Color_id=color_id)
#             context = {'image_list': image_list, 'color': color_id}
#             return render(request, 'admin_main/product_variant_images.html', context)
#
#         except ColorVariant.DoesNotExist:
#             return HttpResponseBadRequest("ColorVariant does not exist.")
#
#     return HttpResponseBadRequest("Invalid request method.")


from PIL import Image

from django.core.files.images import ImageFile
from io import BytesIO
def product_variant_images_add(request):
    if request.method == 'POST':
        color_id = request.POST.get('color')
        product_images = request.FILES.getlist('image_list[]')

        try:
            color = ColorVariant.objects.get(uid=color_id)

            for image in product_images:
                product_image = ProductImage(product=color.product_id, Color_id=color)

                # Resize the image to a standard size
                new_width, new_height = 500, 500  # Set the desired width and height
                img = Image.open(image)
                img.thumbnail((new_width, new_height))

                # Save the resized image to the media path
                image_name = image.name
                img_io = BytesIO()
                img.save(img_io, format='JPEG')  # Use the appropriate format (JPEG, PNG, etc.)
                image_file = ImageFile(img_io, name=image_name)

                # Save the image path to the product_image object and save it to the database
                product_image.image = image_file
                product_image.save()

            image_list = ProductImage.objects.filter(Color_id=color_id)
            context = {'image_list': image_list, 'color': color_id}
            return render(request, 'admin_main/product_variant_images.html', context)

        except ColorVariant.DoesNotExist:
            return HttpResponseBadRequest("ColorVariant does not exist.")

    return HttpResponseBadRequest("Invalid request method.")


def product_image_delete(request, image_id,color):
    image = get_object_or_404(ProductImage, uid=image_id)

    image_file_path = os.path.join(settings.MEDIA_ROOT, image.image.name)
    if os.path.exists(image_file_path):
        try:
            os.remove(image_file_path)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    image.delete()
    return redirect('product_variant_images', color=color)

#@login_required('admin_login')
def admin_product_update(request):
    if request.method == 'POST':
        product_name = request.POST.get('productname')
        product_price = request.POST.get('productprice')
        category_id = request.POST.get('category')
        product_description = request.POST.get('product_description')
        color_variants = request.POST.getlist('color_variant[]')
        color_prices = request.POST.getlist('color_price[]')
        size_variants = request.POST.getlist('size_variant[]')
        size_prices = request.POST.getlist('size_price[]')

        color_quantity = request.POST.getlist('color_quantity[]')
        size_quantity = request.POST.getlist('size_quantity[]')

        print("**************************",category_id)
        product_images = request.FILES.getlist('product_images[]')
        id = request.POST['id']

        category = None
        if category_id:
            category = Category.objects.get(uid=category_id)

        product = Products.objects.get(uid=id)
        product.product_name=product_name
        product.price=product_price
        product.category=category
        product.product_description=product_description
        product.save()
        # image=pic

        for i in range(len(color_variants)):
            color_variant = ColorVariant.objects.create(
                color_name=color_variants[i],
                price=color_prices[i],
                quantity=color_quantity[i]
            )
            product.color_variant.add(color_variant)

        for i in range(len(size_variants)):
            size_variant = SizeVariant.objects.create(
                size_name=size_variants[i],
                price=size_prices[i],
                quantity = size_quantity[i]
            )
            product.size_variant.add(size_variant)
        return redirect('admin_product_update')

    categories = Category.objects.all()
    id = request.GET['id']
    product = Products.objects.get(uid=id)
    return render(request, 'admin_main/admin_product_update.html', {'category_list': categories,'product':product})

# ColorVariant,SizeVariant,ProductImage
#@login_required('admin_login')
def add_remove_product_to_store(request, product_id):
    if product_id:
        print("*******************************",product_id)
        product = Products.objects.get(uid=product_id)
        if product.in_store == False:
            c = ColorVariant.objects.filter(product_id=product_id)
            s = ColorVariant.objects.filter(product_id=product_id)
            i = ProductImage.objects.filter(product=product)
            if len(c)!=0 and len(s)!=0 and len(i)!=0:
                # product.is_deleted = False
                product.in_store=True
                product.save()
                messages.success(request, 'Product is Added to Store.')
            else:
                messages.info(request, 'Product Can not be added to store, Please check if Variants and Images are added.')
        else:
            c = ColorVariant.objects.filter(product_id=product_id)
            s = ColorVariant.objects.filter(product_id=product_id)
            i = ProductImage.objects.filter(product=product)
            if len(c) != 0 and len(s) != 0 and len(i) != 0:
                # product.is_deleted = False
                product.in_store = False
                product.save()
                messages.info(request, 'Product is Removed from Store.')

    return redirect('admin_products_view')

#@login_required('admin_login')
def admin_order_details_view(request):
    order_list = Order.objects.all()
    context = {'order_list':order_list}
    return render(request, 'admin_main/admin_order_details_view.html',context)

#@login_required('admin_login')
def admin_order_info_view(request,order):
    order = Order.objects.get(id=order)
    order_details = OrderProduct.objects.filter(order=order)
    context = {'order_details':order_details,'order':order}
    return render(request, 'admin_main/admin_order_info_view.html',context)

#@login_required('admin_login')
def order_status_update(request):
    if request.method == 'POST':
        id = request.POST['id']
        status = request.POST['status']
        order = Order.objects.get(id=id)
        order.status=status
        order.save()
        messages.info(request, 'Order Status Updated')
        return redirect('admin_order_info_view', order=order.id)

############################################################################################################


def _cart_id(request):
    cart = request.session.session_key
    if not cart:
        cart = request.session.create()
    return cart


from . models import uCart, CartItems
def add_to_cart(request):
    if request.method == 'POST':
        product_id = request.POST.get('product_id')
        size_id = request.POST.get('size_id')
        if request.user.is_authenticated:
            if size_id:
                product = Products.objects.get(uid=product_id)
                variant = SizeVariant.objects.get(uid=size_id)
                try:
                    cart_item = CartItems.objects.get(product_variant=variant, user=request.user)
                    if variant.stock > 0:
                        variant.stock -= 1
                        cart_item.quantity += 1
                        cart_item.save()
                        variant.save()
                    else:
                        messages.info(request, 'Product Out of stock Available')
                except CartItems.DoesNotExist:
                    cart_item = CartItems.objects.create(product=product, quantity=1, user=request.user, product_variant=variant)
                    variant.stock -= 1
                    variant.save()
                    cart_item.save()
                return redirect('cart')
            else:
                messages.error(request, 'Please Select a Color and Size')
                return redirect('product_details', product_id=product_id)

        else:
            if size_id:
                product = Products.objects.get(uid=product_id)
                variant = SizeVariant.objects.get(uid=size_id)
                try:
                    cart = uCart.objects.get(cart_id=_cart_id(request))
                except uCart.DoesNotExist:
                    cart = uCart.objects.create(cart_id=_cart_id(request))
                cart.save()

                try:
                    cart_item = CartItems.objects.get(product_variant=variant, cart=cart)
                    if variant.stock>0:
                        variant.stock -= 1
                        cart_item.quantity += 1
                        cart_item.save()
                        variant.save()
                    else:
                        messages.info(request, 'Product Out of stock Available')
                except CartItems.DoesNotExist:
                    cart_item = CartItems.objects.create(product=product, quantity=1, cart=cart, product_variant=variant)
                    variant.stock -= 1
                    variant.save()
                    cart_item.save()
                return redirect('cart')
            else:
                messages.error(request,'Please Select a Color and Size')
                return redirect('product_details', product_id=product_id)

def add_to_cart_1(request):
    product_id = request.GET['product_id']
    size_id = request.GET['size_id']
    product = Products.objects.get(uid=product_id)
    variant = SizeVariant.objects.get(uid=size_id)
    if request.user.is_authenticated:
        try:
            cart_item = CartItems.objects.get(product_variant=variant, user=request.user)
            if variant.stock > 0:
                variant.stock -= 1
                cart_item.quantity += 1
                cart_item.save()
                variant.save()
            else:
                messages.info(request, 'Product Out of stock Available')
        except CartItems.DoesNotExist:
            cart = uCart.objects.get(cart_id=request.user)
            cart_item = CartItems.objects.create(product=product, quantity=1, cart=cart, product_variant=size_id)
            variant.stock -= 1
            variant.save()
            cart_item.save()
        return redirect('cart')
    else:
        cart = uCart.objects.get(cart_id=_cart_id(request))
        try:
            cart_item = CartItems.objects.get(product_variant=size_id, cart=cart)
            if variant.stock>0:
                variant.stock -= 1
                cart_item.quantity += 1
                cart_item.save()
                variant.save()
            else:
                messages.info(request, 'Product Out of stock Available')
        except CartItems.DoesNotExist:
            cart_item = CartItems.objects.create(product=product, quantity=1, cart=cart, product_variant=size_id)
            variant.stock -= 1
            variant.save()
            cart_item.save()
        return redirect('cart')



def remove_from_cart(request):
    product_id = request.GET['product_id']
    size_id = request.GET['size_id']
    print("*********************REMOVE FROM CART*************************")
    if request.user.is_authenticated:
        variant = SizeVariant.objects.get(uid=size_id)
        try:
            # variant = SizeVariant.objects.get(uid=size_id)
            cart_item = CartItems.objects.get(product_variant=size_id, user=request.user)

            variant.stock += cart_item.quantity
            variant.save()
            cart_item.delete()

            if cart_item.quantity == 0:
                cart_item.delete()
        except CartItems.DoesNotExist:
            return redirect('cart')

        return redirect('cart')
    else:
        # product = Products.objects.get(uid=product_id)
        variant = SizeVariant.objects.get(uid=size_id)
        cart = uCart.objects.get(cart_id=_cart_id(request))
        try:
            # variant = SizeVariant.objects.get(uid=size_id)
            cart_item = CartItems.objects.get(product_variant=size_id, cart=cart)

            variant.stock += cart_item.quantity
            variant.save()
            cart_item.delete()

            if cart_item.quantity == 0:
                cart_item.delete()
        except CartItems.DoesNotExist:
            return redirect('cart')

        return redirect('cart')


def remove_from_cart_1(request):
    product_id = request.GET['product_id']
    size_id = request.GET['size_id']
    print("*********************REMOVE FROM CART*************************")
    product = Products.objects.get(uid=product_id)
    variant = SizeVariant.objects.get(uid=size_id)
    print("*******************",request.user)
    if request.user.is_authenticated:
        try:
            cart_item = CartItems.objects.get(product_variant=size_id, user=request.user)

            variant.stock += 1
            cart_item.quantity -= 1
            cart_item.save()
            variant.save()

            if cart_item.quantity == 0:
                cart_item.delete()
        except CartItems.DoesNotExist:
            return redirect('cart')

        return redirect('cart')
    else:
        cart = uCart.objects.get(cart_id=_cart_id(request))
        try:
            # variant = SizeVariant.objects.get(uid=size_id)
            cart_item = CartItems.objects.get(product_variant=size_id, cart=cart)

            variant.stock += 1
            cart_item.quantity -= 1
            cart_item.save()
            variant.save()

            if cart_item.quantity == 0:
                cart_item.delete()
        except CartItems.DoesNotExist:
            return redirect('cart')

        return redirect('cart')


def cart(request,total=0,quantity=0,cart_items=None):
    tax=0
    grant_total=0
    try:
        if request.user.is_authenticated:
            cart_items = CartItems.objects.filter(user=request.user, is_active=True)
        else:
            cart = uCart.objects.get(cart_id=_cart_id(request))
            cart_items = CartItems.objects.filter(cart=cart, is_active=True)

        for cart_item in cart_items:
            total += (cart_item.product_variant.price * cart_item.quantity)
            quantity += cart_item.quantity
        tax = (2*total)/100
        grant_total = total+tax
    except:
        pass

    size_variant = SizeVariant.objects.all()
    color_variant = ColorVariant.objects.all()
    context = {'total':total,
               'quantity':quantity,
               'cart_items':cart_items,
               'size_variant':size_variant,
               'color_variant':color_variant,
               'tax':tax,
               'grant_total':grant_total
               }
    return render(request, 'store/cart.html', context)


from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
def view_store(request,category=None):
    if category != None:
        c = Category.objects.get(slug=category)
        product_list = Products.objects.all().filter(is_deleted=False,in_store=True,category=c).order_by('uid')
        category_list = Category.objects.all()
        paginator = Paginator(product_list, 3)
        page = request.GET.get('page')
        paged_product = paginator.get_page(page)
        wish_list = WishList.objects.filter(user=request.user)
        print("********",wish_list)
        context = {'product_list': paged_product, 'category_list': category_list,'wish_list':wish_list}
        return render(request, 'store/store.html', context)
    else:
        product_list = Products.objects.all().filter(in_store=True).order_by('uid')
        category_list = Category.objects.all()
        paginator = Paginator(product_list,3)
        page=request.GET.get('page')
        paged_product = paginator.get_page(page)
        wish_list = WishList.objects.filter(user=request.user)
        context = {'product_list':paged_product, 'category_list':category_list}
        return render(request, 'store/store.html', context)

def filter_products(request):
    pass

@login_required(login_url='login')
def user_dashboard(request):
    orders = Order.objects.filter(user=request.user).order_by('-id')
    context = {'orders':orders}
    return render(request, 'user/user_dashboard.html', context)



@login_required(login_url='login')
def checkout(request,total=0,quantity=0,cart_items=None):
    if request.user.is_authenticated:
        try:
            cart_items = CartItems.objects.filter(user=request.user,is_active=True)
            for cart_item in cart_items:
                total += (cart_item.product.price * cart_item.quantity)
                quantity += cart_item.quantity
        except:
            pass

        size_variant = SizeVariant.objects.all()
        color_variant = ColorVariant.objects.all()

        yr = int(datetime.date.today().strftime('%Y'))
        dt = int(datetime.date.today().strftime('%d'))
        mt = int(datetime.date.today().strftime('%m'))
        d = datetime.date(yr, mt, dt)
        cur_date = d.strftime('%Y%m%d')
        address_list = ShippingAddress.objects.filter(user=request.user)

        context = {'total':total,
                   'quantity':quantity,
                   'cart_items':cart_items,
                   'size_variant':size_variant,
                   'color_variant':color_variant,
                   'address_list':address_list

                   }
        return render(request, 'user/checkout.html', context)
    else:
        return redirect('login')


def load_address(request,total=0,quantity=0,cart_items=None):
    if request.user.is_authenticated:
        try:
            cart_items = CartItems.objects.filter(user=request.user,is_active=True)
            for cart_item in cart_items:
                total += (cart_item.product.price * cart_item.quantity)
                quantity += cart_item.quantity
        except:
            pass

        size_variant = SizeVariant.objects.all()
        color_variant = ColorVariant.objects.all()

        yr = int(datetime.date.today().strftime('%Y'))
        dt = int(datetime.date.today().strftime('%d'))
        mt = int(datetime.date.today().strftime('%m'))
        d = datetime.date(yr, mt, dt)
        cur_date = d.strftime('%Y%m%d')
        address_list = ShippingAddress.objects.filter(user=request.user)
        address_id = request.GET.get('address_id')
        address=None
        if address_id != 0:
            address = ShippingAddress.objects.filter(id=address_id)
        print(address)
        context = {'total':total,
                   'quantity':quantity,
                   'cart_items':cart_items,
                   'size_variant':size_variant,
                   'color_variant':color_variant,
                   'address_list':address_list,
                   'address': address
                   }
        return render(request, 'user/checkout.html', context)
    else:
        return redirect('login')


from . models import Order, Payment, OrderProduct
from . forms import OrderForm
import datetime
def place_order(request, total=0,quantity=0):
    cur_user = request.user
    cart_items = CartItems.objects.filter(user=cur_user)
    cart_count = cart_items.count()
    if cart_count <= 0:
        return redirect('view_store')

    grant_total = 0
    tax = 0
    total,quantity=0,0
    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        quantity += cart_item.quantity
    tax = (2*total)/100
    grant_total=total+tax

    if request.method == 'POST':
        form = OrderForm(request.POST)
        cod = request.POST['cod']
        if cod == 'True':
            payment = Payment.objects.create(
                user=request.user,
                payment_method = 'cod',
            )
            payment.save()
        address = ShippingAddress.objects.get(user=request.user,is_default=True)
        # if form.is_valid():
        data = Order()
        data.user=request.user
        data.first_name = address.first_name
        data.last_name = address.last_name#form.cleaned_data['last_name']
        data.phone = address.phone
        data.email = address.email
        data.address_line_1 = address.address_line_1
        data.address_line_2 = address.address_line_2
        data.country = address.country
        data.state = address.state
        data.city = address.city
        data.pincode = address.pincode
        data.order_total = grant_total
        data.tax = tax
        data.ip = request.META.get('REMOTE_ADDR')
        data.payment = payment
        data.save()

        #Generating Order Number
        yr = int(datetime.date.today().strftime('%Y'))
        dt = int(datetime.date.today().strftime('%d'))
        mt = int(datetime.date.today().strftime('%m'))
        d = datetime.date(yr,mt,dt)
        cur_date = d.strftime('%Y%m%d')
        order_number = cur_date + str(data.id)
        data.order_number = order_number
        data.save()

        for item in cart_items:
            order_product=OrderProduct.objects.create(
                user=request.user,
                product=item.product,
                product_price=(item.product.price * item.quantity),
                quantity=item.quantity,
                size=item.product_variant.size,
                payment=payment,
                color=item.product_variant.Color_id.color,
                order=data
            )
            order_product.save()
        cartitems = CartItems.objects.filter(user=cur_user)
        cartitems.delete()
        order = Order.objects.get(user=cur_user, is_ordered=False, order_number=order_number)
        order_items = OrderProduct.objects.filter(order=order)
        quantity = 0
        for item in order_items:
            total += (item.product.price * item.quantity)
            quantity += item.quantity
        context = {
            'order': order,
            'order_items': order_items,
            'total': total,
            'tax': tax,
            'grand_total': grant_total,
        }
        return render(request, 'user/payment.html', context)
    else:
        return redirect(request, "checkout")



def payments(request,orderno=0):
    print("*******************PAYMENTS********************")
    print("***************************************ORDERNO=",orderno)
    cur_user = request.user
    order = None
    order_items = None
    total = 0
    try:
        order = Order.objects.get(user=cur_user, is_ordered=False, id=orderno)
        order_items = OrderProduct.objects.filter(order=order)
        quantity = 0
        for item in order_items:
            total += (item.product.price * item.quantity)
            quantity += item.quantity

    except:
        pass

    context = {
        'order': order,
        'order_items': order_items,
        'total': total,
        'tax': order.tax if order else 0,
        'grand_total': order.order_total if order else 0,
    }
    return render(request, 'user/payment.html', context)






def OrderConfirmationEmail(request, user, to_email):
    mail_subject = "Login to your user account Using this OTP."
    message = render_to_string("user/order_confirmation_email.html", {
        'user': f'{user.first_name} {user.last_name}',

    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear {user}, please go to you email {to_email} and check for the OTP \
                Note: Check your spam folder.')
        request.session['otp_sent_timestamp'] = timezone.now().timestamp()
    else:
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')



@login_required(login_url='login')
def order_details(request, orderno):
    order = Order.objects.get(id=orderno)
    print(order)
    order_product_list = OrderProduct.objects.filter(order=order)
    context = {'order_product_list':order_product_list,'orderno':orderno,'order':order}
    return render(request, 'user/order_details.html', context)

@login_required(login_url='login')
def cancel_order(request, orderno):
    order = Order.objects.get(id=orderno)
    order.status = 'Cancelled'
    order.save()
    messages.info(request, 'Order Cancelled')
    return redirect('order_details',orderno=orderno)


from . models import Coupons
def admin_coupons_view(request):
    if request.user.is_authenticated and request.user.is_superuser:
        coupons_list = Coupons.objects.all()
        context = {'coupons_list':coupons_list}
        return render(request, 'admin_main/admin_manage_coupons.html',context)


def admin_coupons_add(request):
    if request.user.is_authenticated and request.user.is_superuser:
        coupon_code = request.POST.get('coupon_code')
        MinPurchase = request.POST.get('MinPurchase')
        ExpDate = request.POST.get('ExpDate')
        amount = request.POST.get('amount')
        if Coupons.objects.filter(coupon_code=coupon_code).exists():
            messages.warning(request, "Coupon Code is not Unique!")
            return redirect('admin_coupons_view')

        coupon = Coupons(coupon_code=coupon_code,
                         MinPurchase=MinPurchase,
                         ExpDate=ExpDate,
                         amount=amount)
        coupon.save()
        messages.success(request, "New Coupon Added")
        return redirect('admin_coupons_view')



def admin_coupons_update(request):
    if request.user.is_authenticated and request.user.is_superuser:
        if request.method == 'POST':
            coupon_code = request.POST.get('coupon_code')
            MinPurchase = request.POST.get('MinPurchase')
            ExpDate = request.POST.get('ExpDate')
            amount = request.POST.get('amount')
            coupon_id = request.POST.get('coupon_id')

            coupon = Coupons.objects.get(id=coupon_id)
            coupon.coupon_code=coupon_code
            coupon.MinPurchase=MinPurchase
            coupon.ExpDate=ExpDate
            coupon.amount=amount
            coupon.save()
            messages.success(request, "Coupon Details Updated")
            return redirect('admin_coupons_view')
        else:
            coupon_id = request.GET.get('coupon_id')
            coupon=Coupons.objects.get(id=coupon_id)
            coupons_list = Coupons.objects.all()
            edit = True
            context = {'coupons_list': coupons_list, 'coupon':coupon, 'edit':edit}
            return render(request, 'admin_main/admin_manage_coupons.html', context)



def admin_coupons_delete(request):
    if request.user.is_authenticated and request.user.is_superuser:
        coupon_id = request.GET.get('coupon_id')
        coupon = Coupons.objects.get(id=coupon_id)
        coupon.delete()
        messages.info(request, 'Coupon Deleted')
        return redirect('admin_coupons_view')



from django.urls import reverse
from django.shortcuts import render
from paypal.standard.forms import PayPalPaymentsForm




def paypal_request(request):
    paypal_dict = {
        "business": "fashionstoremerchant@gmail.com",
        "amount": "100.00",
        "item_name": "name of the item",
        "invoice": "unique-invoice-id",
        "notify_url": request.build_absolute_uri(reverse('paypal-ipn')),
        "return": request.build_absolute_uri(reverse('payment')),
        "cancel_return": request.build_absolute_uri(reverse('payment')),
        "custom": "premium_plan",  # Custom command to correlate to some function later (optional)
    }

    # Create the instance.
    form = PayPalPaymentsForm(initial=paypal_dict)
    context = {"form": form}
    return render(request, "user/payment.html", context)


def user_settings(request):
    return render(request, 'user/user_settings.html')

import json
def confirm_payments(request):
    body = json.loads(request.body)
    print(body)
    payment = Payment(user=request.user,
                      payment_id=body['transID'],
                      order_number=body['orderID'],
                      payment_method=body['payment_method'],
                      status=body['status'])
    payment.save()
    order = Order.objects.get(order_number=body['orderID'])
    order.payment = payment
    order.save()
    order_items = OrderProduct.objects.filter(order=order)
    for item in order_items:
        item.payment=payment
        item.ordered=True
        item.save()
    data = {
        'order_number': order.order_number,
        'transID': payment.payment_id,
    }
    return JsonResponse(data)
    # return render(request, 'user/payment.html')


# def order_complete(request):
#     order_number = request.GET.get('order_number')
#     transID = request.GET.get('payment_id')
# 	print("************************************",order_number,transID)
#     try:
#         order = Order.objects.get(order_number=order_number, is_ordered=True)
#         ordered_products = OrderProduct.objects.filter(order_id=order.id)
#
#         subtotal = 0
#         for i in ordered_products:
#             subtotal += i.product_price * i.quantity
#
#         payment = Payment.objects.get(payment_id=transID)
#
#         context = {
#             'order': order,
#             'ordered_products': ordered_products,
#             'order_number': order.order_number,
#             'transID': payment.payment_id,
#             'payment': payment,
#             'subtotal': subtotal,
#         }
#         return render(request, 'orders/order_complete.html', context)
#     except (Payment.DoesNotExist, Order.DoesNotExist):
#         return redirect('index')


def order_complete(request):
    order_number = request.GET.get('order_number')
    transID = request.GET.get('payment_id')
    print("************************************", order_number, transID)

    try:
        order = Order.objects.get(order_number=order_number)#, is_ordered=True
        ordered_products = OrderProduct.objects.filter(order_id=order.id)

        subtotal = 0
        for i in ordered_products:
            subtotal += i.product_price * i.quantity

        payment = Payment.objects.get(payment_id=transID)

        context = {
            'order': order,
            'ordered_products': ordered_products,
            'order_number': order.order_number,
            'transID': payment.payment_id,
            'payment': payment,
            'subtotal': subtotal,
        }
        return render(request, 'store/order_complete.html', context)
    except (Payment.DoesNotExist, Order.DoesNotExist):
        return redirect('index')


def apply_coupon(request):
    if request.method == 'POST':
        order_id = request.POST.get('order_id')
        coupon_code = request.POST.get('coupon_code')
        orderno=order_id
        try:
            order = Order.objects.get(id=order_id)
            coupon = Coupons.objects.get(coupon_code=coupon_code)
            if order.order_total>=float(coupon.MinPurchase):
                order.order_total -= float(coupon.amount)
                order.save()
                return redirect('payments', orderno=orderno)
            else:
                messages.info(request, "Check Minimum Purchase")
                return redirect('payments', orderno=orderno)
        except:
            messages.info(request, "Sorry Can not Apply this Coupon")
            return redirect('payments', orderno=orderno)



def user_profile_view(request):
    user = User.objects.get(id=request.user.id)
    u = Customer.objects.get(user=user)
    context = {'user':user,'u':u}
    return render(request, 'user/user_profile_view.html', context)


def user_profile_edit(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        contact = request.POST.get('contact')
        user = User.objects.get(id=request.user.id)
        try:
            u = Customer.objects.get(user=user)
        except:
            u = Customer(user=user)
            u.save()
        user.username=email
        user.email=email
        user.first_name=first_name
        user.last_name=last_name
        u.contact=contact
        u.email=email
        user.save()
        u.save()
        messages.success(request, 'Profile Updated')
        return redirect('user_profile_view')

    user = User.objects.get(id=request.user.id)
    u = Customer.objects.get(user=user)
    context = {'user': user, 'u': u}
    return render(request, 'user/user_profile_edit.html', context)

from . models import ShippingAddress
def user_address_view(request):
    address_list = ShippingAddress.objects.filter(user=request.user)
    context = {'address_list':address_list}
    return render(request, 'user/user_address_view.html', context)


def user_address_add(request):
    if request.method=='POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        address_line_1 = request.POST.get('address_line_1')
        address_line_2 = request.POST.get('address_line_2')
        country = request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        pincode = request.POST.get('pincode')

        user = User.objects.get(id=request.user.id)

        address = ShippingAddress(user=user,
                                  first_name=first_name,
                                  last_name=last_name,
                                  phone=phone,
                                  email=email,
                                  address_line_1=address_line_1,
                                  address_line_2=address_line_2,
                                  country=country,
                                  state=state,
                                  city=city,
                                  pincode=pincode)
        address.save()
        messages.success(request, 'Address Added')
        return render(request, 'user/user_address_add.html')
    else:
        return render(request, 'user/user_address_add.html')



def user_address_edit(request):
    if request.method=='POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        address_line_1 = request.POST.get('address_line_1')
        address_line_2 = request.POST.get('address_line_2')
        country = request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        pincode = request.POST.get('pincode')
        address_id = request.POST.get('address_id')
        address = ShippingAddress.objects.get(id=address_id)

        # user = user,
        address.first_name = first_name
        address.last_name = last_name
        address.phone = phone
        address.email = email
        address.address_line_1 = address_line_1
        address.address_line_2 = address_line_2
        address.country = country
        address.state = state
        address.city = city
        address.pincode = pincode
        address.save()
        context = {'address': address}
        return render(request, 'user/user_address_edit.html', context)
    else:
        address_id = request.GET.get('address_id')
        address = ShippingAddress.objects.get(id=address_id)
        context = {'address':address}
        return render(request, 'user/user_address_edit.html', context)


def user_address_delete(request):
    address_id = request.GET.get('address_id')
    address = ShippingAddress.objects.get(id=address_id)
    address.delete()
    messages.success(request, 'Address Deleted')
    return redirect('user_address_view')


from . models import WishList
def add_item_to_wish_list(request, product_id):
    try:
        user = request.user
        product = Products.objects.get(uid=product_id)
        wish = WishList.objects.get(user=user, product=product)
        if wish is not None:
            messages.info(request, 'Item already in wishlist')
        return redirect('view_store')
    except WishList.DoesNotExist:
        user = request.user
        product = Products.objects.get(uid=product_id)
        wish = WishList(user=user, product=product)
        wish.save()
        return redirect('view_store')



def remove_item_from_wish_list(request):
    product_id = request.GET.get('product_id')
    wish = WishList.objects.get(id=product_id)
    wish.delete()
    return redirect('view_store')

def user_wish_list_view(request):
    wish_product_list = WishList.objects.all().filter(user=request.user)
    context = {'wish_product_list':wish_product_list}
    return render(request, 'user/user_wish_list_view.html', context)


def user_view_transaction_details(request):
    transaction_list = Payment.objects.all().filter(user=request.user)
    context = {'transaction_list':transaction_list}
    return render(request, 'user/user_view_transaction_details.html', context)



def select_address(request,address_id):
    print(address_id)
    address = ShippingAddress.objects.get(id=address_id)
    address.is_default=True
    address.save()
    address_list = ShippingAddress.objects.filter(user=request.user).exclude(id=address_id)
    for ad in address_list:
        ad.is_default = False
        ad.save()
    return redirect('checkout')
