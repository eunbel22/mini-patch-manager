from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.routers import DefaultRouter

from patchmgr import views

router = DefaultRouter()
router.register('groups', views.EndpointGroupViewSet, basename='group')
router.register('endpoints', views.EndpointViewSet, basename='endpoint')
router.register('cves', views.CVEViewSet, basename='cve')
router.register('patches', views.PatchViewSet, basename='patch')
router.register('policies', views.PolicyViewSet, basename='policy')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
