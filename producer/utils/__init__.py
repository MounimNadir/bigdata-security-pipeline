from .ip_pool import (
    get_source_ip,
    get_malicious_ip,
    get_normal_external_ip,
    get_internal_server_ip,
    get_employee_ip,
    get_country,
    is_blacklisted,
    BLACKLIST_CIDRS,
)

from .geo_lookup import get_country, is_blacklisted