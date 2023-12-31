# Generated by Django 4.2.3 on 2023-07-26 04:13

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('store', '0027_coupons'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='shippingaddress',
            name='address',
        ),
        migrations.RemoveField(
            model_name='shippingaddress',
            name='customer',
        ),
        migrations.RemoveField(
            model_name='shippingaddress',
            name='date_added',
        ),
        migrations.RemoveField(
            model_name='shippingaddress',
            name='order',
        ),
        migrations.RemoveField(
            model_name='shippingaddress',
            name='zipcode',
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='address_line_1',
            field=models.CharField(default=1, max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='address_line_2',
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='country',
            field=models.CharField(default=1, max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='email',
            field=models.EmailField(default=1, max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='first_name',
            field=models.CharField(default=1, max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='last_name',
            field=models.CharField(default=1, max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='phone',
            field=models.CharField(default=1, max_length=15),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='pincode',
            field=models.CharField(default=1, max_length=10),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingaddress',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='shippingaddress',
            name='city',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='shippingaddress',
            name='state',
            field=models.CharField(max_length=50),
        ),
    ]
