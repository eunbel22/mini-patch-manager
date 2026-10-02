from django.contrib import admin

from . import models

admin.site.register([
    models.EndpointGroup,
    models.Endpoint,
    models.Software,
    models.InstalledSoftware,
    models.CVE,
    models.AffectedSoftware,
    models.Patch,
    models.PatchStatus,
    models.Policy,
    models.PolicyStage,
    models.Deployment,
])
