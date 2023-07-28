from store.models import Category,uCart,CartItems
from .views import _cart_id
def category_list_processor(request):
    category_list = Category.objects.all()
    return {'category_list': category_list}

def cart_counter(request):
    cart_count = 0
    try:
        if request.user.is_authenticated:
            cart_items = CartItems.objects.all().filter(user=request.user)
        else:
            cart = uCart.objects.filter(cart_id=_cart_id(request))
            cart_items = CartItems.objects.all().filter(cart=cart[:1])
        for cart_item in cart_items:
            cart_count += cart_item.quantity
    except uCart.DoesNotExist:
        cart_count=0
    return dict(cart_count=cart_count)