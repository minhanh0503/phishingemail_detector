from backend.analyzer.email_domain_analyzer import analyze_sender_email
from backend.analyzer.whois_analyzer import analyze_domain_whois

result = analyze_sender_email(
    email="support@paypa1-secure.com",
    display_name="PayPal Support"
)
print(result)

print(analyze_domain_whois("paypal.com"))
print(analyze_domain_whois("secure-paypal-login-verify.xyz"))

from backend.utils.urls_utils import extract_urls, extract_domain_from_url
from backend.analyzer.urldomain_analyzer import analyze_url_domain

email_body = """
Hello,

Please verify your account immediately:
https://secure-paypal-login-verify.xyz/auth
Or click http://192.168.1.1/login
Short link: bit.ly/3fake

Thanks,
PayPal Security
"""

urls = extract_urls(email_body)
print("Extracted URLs:", urls)

for url in urls:
    domain = extract_domain_from_url(url)
    analysis = analyze_url_domain(domain, sender_domain="paypal.com")
    print(domain, analysis)

from backend.analyzer.riskengine_analyzer import analyze_email_risk

email_body = """
Dear user,

Your PayPal account has been limited.
Verify immediately:
https://secure-paypal-login-verify.xyz/auth
Short link: bit.ly/3fake

Failure to act will result in suspension.
"""

result = analyze_email_risk(
    sender_email="security@paypa1-support.com",
    email_body=email_body
)

from pprint import pprint
pprint(result)
