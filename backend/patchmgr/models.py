from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class Severity(models.TextChoices):
    """CVSS 3.1 등급 (Low 0.1~3.9, Medium 4.0~6.9, High 7.0~8.9, Critical 9.0~10.0)"""

    LOW = 'low', 'Low'
    MEDIUM = 'medium', 'Medium'
    HIGH = 'high', 'High'
    CRITICAL = 'critical', 'Critical'


class EndpointGroup(models.Model):
    """PC 그룹 (테스트 · 일반 · 예외). Django 기본 Group과 이름이 겹쳐 EndpointGroup으로 둔다."""

    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class Endpoint(models.Model):
    """가상 PC 한 대"""

    hostname = models.CharField(max_length=100, unique=True)
    os_name = models.CharField(max_length=100)
    os_build = models.CharField(max_length=50)
    group = models.ForeignKey(EndpointGroup, on_delete=models.PROTECT, related_name='endpoints')
    last_reported_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.hostname


class Software(models.Model):
    """소프트웨어 종류"""

    name = models.CharField(max_length=200)
    vendor = models.CharField(max_length=200, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['name', 'vendor'], name='uniq_software_name_vendor'),
        ]

    def __str__(self):
        return self.name


class InstalledSoftware(models.Model):
    """PC에 설치된 소프트웨어와 버전"""

    endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE, related_name='installed_software')
    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name='installations')
    version = models.CharField(max_length=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['endpoint', 'software'], name='uniq_installed_endpoint_software'),
        ]

    def __str__(self):
        return f'{self.endpoint} - {self.software} {self.version}'


class SoftwareCpe(models.Model):
    """우리 소프트웨어와 NVD의 제조사:제품 이름(CPE)을 잇는 매핑.

    소프트웨어 하나에 NVD 이름이 여러 개일 수 있어서(예: Adobe Reader는 acrobat_reader와
    acrobat_reader_dc, Notepad++는 제조사 이름이 세 가지) 칸이 아니라 표로 둔다.
    vendor와 product는 CPE 표기에서 역슬래시를 뺀 소문자 값이다 (예: notepad-plus-plus, notepad++).
    """

    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name='cpes')
    vendor = models.CharField(max_length=100)
    product = models.CharField(max_length=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['software', 'vendor', 'product'], name='uniq_softwarecpe'),
        ]

    def __str__(self):
        return f'{self.software} = {self.vendor}:{self.product}'


class CVE(models.Model):
    """NVD에서 수집한 취약점"""

    cve_id = models.CharField(max_length=30, unique=True)
    description = models.TextField(blank=True)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.cve_id


class AffectedSoftware(models.Model):
    """CVE가 영향을 주는 소프트웨어와 버전 범위 (NVD의 CPE 범위).

    범위 칸은 NVD와 같은 네 가지(이상 · 초과 · 이하 · 미만)이고, 범위 없이 특정 버전 하나만 지정된 경우는
    version_exact에 둔다. 비어 있는 칸은 그 조건이 없다는 뜻이다. 모두 비어 있으면 모든 버전이 해당된다.
    """

    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='affected_software')
    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name='affected_by')
    version_start_including = models.CharField(max_length=100, blank=True)
    version_start_excluding = models.CharField(max_length=100, blank=True)
    version_end_including = models.CharField(max_length=100, blank=True)
    version_end_excluding = models.CharField(max_length=100, blank=True)
    version_exact = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f'{self.cve} -> {self.software}'


class Patch(models.Model):
    """KB 하나. 같은 CVE라도 Windows 종류마다 KB가 다르므로 target_os를 둔다."""

    kb_number = models.CharField(max_length=20)
    title = models.CharField(max_length=300, blank=True)
    target_os = models.CharField(max_length=100)
    fixed_build = models.CharField(max_length=50, blank=True)
    release_date = models.DateField(null=True, blank=True)
    download_url = models.URLField(max_length=500, blank=True)
    is_error_reported = models.BooleanField(default=False)
    cves = models.ManyToManyField(CVE, related_name='patches', blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['kb_number', 'target_os'], name='uniq_patch_kb_os'),
        ]

    def __str__(self):
        return f'{self.kb_number} ({self.target_os})'


class PatchStatus(models.Model):
    """PC와 패치 한 쌍의 적용 상태"""

    class Status(models.TextChoices):
        PENDING = 'pending', '미적용'
        APPLIED = 'applied', '적용'
        ERROR = 'error', '오류'
        ROLLED_BACK = 'rolled_back', '롤백'

    endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE, related_name='patch_statuses')
    patch = models.ForeignKey(Patch, on_delete=models.CASCADE, related_name='statuses')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    error_code = models.CharField(max_length=50, blank=True)
    reported_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['endpoint', 'patch'], name='uniq_patchstatus_endpoint_patch'),
        ]

    def __str__(self):
        return f'{self.endpoint} / {self.patch}: {self.status}'


class Policy(models.Model):
    """패치 정책 본체. min_severity 이상인 패치가 대상이다."""

    name = models.CharField(max_length=100, unique=True)
    min_severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.HIGH)
    start_time = models.TimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class PolicyStage(models.Model):
    """정책의 배포 단계. order 1이 테스트 그룹, 마지막이 전체."""

    policy = models.ForeignKey(Policy, on_delete=models.CASCADE, related_name='stages')
    order = models.PositiveSmallIntegerField()
    group = models.ForeignKey(EndpointGroup, on_delete=models.PROTECT, related_name='policy_stages')
    delay_minutes = models.PositiveIntegerField(default=0)
    # 이 단계의 오류율(0.0~1.0)이 이 값을 넘으면 롤백한다
    rollback_error_rate = models.FloatField(
        default=0.1,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
    )

    class Meta:
        ordering = ['policy', 'order']
        constraints = [
            models.UniqueConstraint(fields=['policy', 'order'], name='uniq_policystage_policy_order'),
        ]

    def __str__(self):
        return f'{self.policy} #{self.order} ({self.group})'


class Deployment(models.Model):
    """정책을 패치 하나에 실제로 실행한 기록"""

    class State(models.TextChoices):
        RUNNING = 'running', '진행 중'
        COMPLETED = 'completed', '완료'
        ROLLED_BACK = 'rolled_back', '롤백됨'

    policy = models.ForeignKey(Policy, on_delete=models.CASCADE, related_name='deployments')
    patch = models.ForeignKey(Patch, on_delete=models.CASCADE, related_name='deployments')
    current_stage = models.ForeignKey(
        PolicyStage, on_delete=models.SET_NULL, null=True, blank=True, related_name='deployments',
    )
    state = models.CharField(max_length=20, choices=State.choices, default=State.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    # 현재 단계에 들어간 시각. 그 단계의 delay_minutes가 지나야 이 단계의 PC들에게 설치 지시가 나간다.
    stage_started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # 롤백된 까닭 (예: "1단계 오류율 20%가 롤백 기준 10%를 넘어 롤백했습니다.")
    note = models.CharField(max_length=300, blank=True)

    class Meta:
        constraints = [
            # 한 패치에는 진행 중인 배포가 하나만 있을 수 있다 (정책이 달라도 마찬가지)
            models.UniqueConstraint(
                fields=['patch'], condition=models.Q(state='running'), name='uniq_running_deployment_per_patch',
            ),
        ]

    def __str__(self):
        return f'{self.policy} -> {self.patch}: {self.state}'
