from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig


#TODO NLC also scan internal DNS servers?
#TODO NLC scan and pass on srv record data too!!!
#todo nlc what about CAA? SOA? TXT v=spf1? NS? MX? CNAME? ANY? ALIAS, rare record types
#todo validate doh

class dns_techs(BaseModule):
    # RAW_DNS_RECORD covers TXT/MX/SRV/etc. CNAMEs are excluded from RAW_DNS_RECORD
    # emission by dnsresolve.py:207, so we also watch DNS_NAME and read CNAME data
    # directly from event.raw_dns_records.
    watched_events = ["RAW_DNS_RECORD", "DNS_NAME"]
    produced_events = ["FINDING"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Check DNS records for known SaaS/verification/CNAME signatures to fingerprint technologies in use",
        "author": "@SystemNatalie",
        "created_date": "2026-04-29",
    }
    # BBOT 3.x configuration schema. This module has no custom settings.
    class Config(BaseModuleConfig):
        pass

    txt_records = {
        "probely": "The probely record indicates that domain is using Snyk API & Web/Probely for DAST scanning. Also indicates a likelihood of Snyk SAST.",
        "docusign": "This record is used as proof of domain ownership for DocuSign product offerings. This indicates the domain likely uses DocuSign as an e-signature solution.",
        "facebook-domain-verification": "This record is used as proof of domain ownership for use in the Facebook Business Manager.",
        "google-site-verification": "This record is used as proof of ownership for Google G Suite product offerings, however it might simply be verification for Google Analytics.",
        "adobe-sign-verification": "This record is used as proof of ownership of a domain for the Adobe Sign product offering. This indicates the domain likely uses Adobe Sign as an e-signature solution.",
        "atlassian-domain-verification": "This record verifies domain ownership with Atlassian. This indicates the domain might be sending managed emails from an Atlassian property and likely utilizes Atalassian product offerings such as Jira of Confluence.",
        "MS": "This record is used as proof of domain ownership by the Microsoft Office 365 product offering. This indicates a probable usage of at least some Office 365 products.",
        "adobe-idp-site-verification": "This record is used as proof of ownership for use in the Adobe Enterprise Products product offerings.",
        "yandex-verification": "This record is used as proof of ownership of a domain for Yandex. This indicates a probable usage of the Yandex Webmaster Tools.",
        "_amazonses": "Amazon Simple Email Services",
        "logmein-verification-code": "This record is used as proof of ownership for a domain for LogMeIn services. The presence of this record indicates the owner of the domain is likely using LogMeIn for remote troubleshooting.",
        "citrix-verification-code": "This record indicates the domain might be associated with utilizing Citrix Services.",
        "pardot": "This record indicates the domain might be utilizing Pardot B2B Marketing tools from Salesforce.com.",
        "zuora": "This record indicates the domain might be utilizing Zuora subscription management software.",
        "onetrust-domain-verification": "This record indicates the domain might be utilizing OneTrust governance services.",
        "smartsheet-site-validation": "This record indicates the organization might be utilizing SmartSheet as a work management platform.",
        "cisco-ci-domain-verification": "This record suggests that the domain utilizes Cisco Common Identity solutions, typically seen with Webex and Cloud Control",
        "apple-domain-verification": "This record suggests that the domain likely utilizes Apple products in some nature, or that the domain produces iOS/Mac apps.",
        "nintex": "This record indicates the domain is utilizing the Nintex Process Management and Workflow Automation Software.",
        "teamviewer-sso-verification": "This record indicates the domain might be using Teamviewer for remote access and support.",
        "knowbe4-site-verification": "This record indicates the domain is likely using KnowBe4 for security training and phishing tests.",
        "miro-verification": "This record suggests the domain is utilizing Miro for collaboration.",
        "ibmid": "This record suggests the domain is controlled by an IBM Enterprise Federation partner.",
        "windsurf-verification": "This record is used as proof of domain ownership for Windsurf.",
        "stripe-verification": "This record is used as proof of domain ownership for Stripe. This indicates the domain likely uses Stripe for payment processing.",
        "ZOOM_verify": "This record is used as proof of domain ownership for Zoom. This indicates the domain likely uses Zoom for video conferencing and collaboration.",
        "notion-domain-verification": "This record is used as proof of domain ownership for Notion. This indicates the domain likely uses Notion for workspace and documentation.",
        "mongodb-site-verification": "This record is used as proof of domain ownership for MongoDB services. This indicates the domain likely uses MongoDB Atlas or other MongoDB cloud services.",
        "cursor-domain-verification": "This record is used as proof of domain ownership for Cursor.",
        "h1-domain-verification": "This record is used as proof of domain ownership for HackerOne. This indicates the domain likely participates in bug bounty or vulnerability disclosure programs.",
        "cloudhealth": "This record indicates the domain might be utilizing CloudHealth for cloud cost management and optimization.",
        "atlassian-sending-domain-verification": "This record verifies domain ownership for Atlassian email sending. This indicates the domain is configured to send emails through Atlassian services.",
        "docker-verification": "This record is used as proof of domain ownership for Docker. This indicates the domain likely uses Docker Hub or Docker Enterprise services.",
        "drift-domain-verification": "This record is used as proof of domain ownership for Drift. This indicates the domain likely uses Drift for conversational marketing and sales.",
        "segment-site-verification": "This record is used as proof of domain ownership for Segment. This indicates the domain likely uses Segment for customer data infrastructure.",
        "wiz-domain-verification": "This record is used as proof of domain ownership for Wiz. This indicates the domain likely uses Wiz for cloud security.",
        "hcp-domain-verification": "This record is used as proof of domain ownership for HashiCorp Cloud Platform. This indicates the domain likely uses HCP services.",
        "rippling-domain-verification": "This record is used as proof of domain ownership for Rippling. This indicates the domain likely uses Rippling for HR and IT management.",
        "chairot": "This record indicates the domain might be utilizing Chairot services.",
        "thebrief-domain-verification": "This record is used as proof of domain ownership for TheBrief.",
        "hubspot-domain-verification": "This record is used as proof of domain ownership for HubSpot. This indicates the domain likely uses HubSpot for marketing, sales, or CRM.",
        "wombat-verification": "This record is used as proof of domain ownership for Wombat Security. This indicates the domain likely uses Wombat for security awareness training.",
        "afternic-verification": "This record is used as proof of domain ownership for Afternic. This indicates the domain might be listed on the Afternic domain marketplace.",
        "SFMC": "This record indicates the domain might be utilizing Salesforce Marketing Cloud for marketing automation and email campaigns."
    }

    cname_records = {
        "autodiscover.": "This domain appears to be outsourcing Microsoft Exchange.",
        "lyncdiscover.": "This domain appears to be outsourcing Microsoft Lync.",
        "sip.": "This domain appears to be outsourcing Microsoft SIP Services.",
        "enterpriseregistration.": "This domain appears to be outsourcing Mobile Device Management (MDM) services.",
        "enterpriseenrollment.": "This domain appears to be outsourcing Mobile Device Management (MDM) services.",
        "adfs.": "Active Directory Federated Services",
        "sts.": "Security Token Service"
    }

    cname_providers = {
        # Microsoft / Lync / Airwatch
        "outlook": "Microsoft Office 365 (Managed Exchange)",
        "awmdm.com": "Airwatch Mobile Device Management (MDM)",
        "lync.com": "Microsoft Hosted Lync",
        # Security / scanning
        "probely": "The probely record indicates that domain is using Snyk API & Web/Probely for DAST scanning. Also indicates a likelihood of Snyk SAST.",
        # iPaaS / integration platforms
        "cloudhub.io": "The cloudhub.io record indicates that domain is using MuleSoft's CloudHub.io for hosting and/or infrastructure services.",
        # PaaS / serverless hosting
        "herokuapp.com": "Domain points to Heroku - likely a Heroku-hosted application.",
        "herokudns.com": "Domain uses Heroku's custom-domain DNS infrastructure (SSL endpoint).",
        "vercel-dns.com": "Domain points to Vercel - likely a Vercel-hosted frontend or serverless app.",
        "vercel.app": "Domain points to Vercel - likely a Vercel-hosted frontend or serverless app.",
        "netlify.app": "Domain points to Netlify - likely a Netlify-hosted frontend.",
        "netlify.com": "Domain points to Netlify - likely a Netlify-hosted frontend.",
        "pages.dev": "Domain points to Cloudflare Pages - likely a Cloudflare-hosted frontend.",
        "github.io": "Domain points to GitHub Pages - likely a GitHub-hosted static site.",
        "azurewebsites.net": "Domain points to Azure App Service - likely a Microsoft Azure-hosted web app.",
        "cloudapp.net": "Domain points to Azure (legacy Cloud Services) - likely a Microsoft Azure-hosted workload.",
        "cloudapp.azure.com": "Domain points to Azure - likely a Microsoft Azure-hosted workload.",
        "appspot.com": "Domain points to Google App Engine - likely a GAE-hosted application.",
        "run.app": "Domain points to Google Cloud Run - likely a serverless container workload.",
        "elasticbeanstalk.com": "Domain points to AWS Elastic Beanstalk - likely an EB-managed application.",
        "awsapprunner.com": "Domain points to AWS App Runner - likely an App Runner-hosted service.",
        # CDNs / edge / WAF
        "cloudfront.net": "Domain points to AWS CloudFront - content is being served via CloudFront CDN.",
        "fastly.net": "Domain points to Fastly - content is being served via the Fastly CDN.",
        "akamaiedge.net": "Domain points to Akamai - content is being served via Akamai's edge network.",
        "akamai.net": "Domain points to Akamai - content is being served via Akamai's edge network.",
        "edgekey.net": "Domain points to Akamai (edgekey) - content is being served via Akamai's edge network.",
        "edgesuite.net": "Domain points to Akamai (edgesuite) - content is being served via Akamai's edge network.",
        "cdn77.org": "Domain points to CDN77 - content is being served via the CDN77 CDN.",
        "incapdns.net": "Domain points to Imperva (Incapsula) - traffic is fronted by the Imperva WAF/CDN.",
        "sucuri.net": "Domain points to Sucuri - traffic is fronted by the Sucuri WAF/CDN.",
        "cloudflare.net": "Domain points to Cloudflare - traffic is fronted by Cloudflare's CDN/WAF.",
        # CRM / marketing / helpdesk
        "force.com": "Domain points to Salesforce (force.com) - likely a Salesforce-hosted Experience Cloud or community site.",
        "hs-sites.com": "Domain points to HubSpot CMS Hub - likely a HubSpot-hosted marketing site.",
        "hubspot.net": "Domain points to HubSpot - likely a HubSpot-hosted property.",
        "zendesk.com": "Domain points to Zendesk - likely a Zendesk-hosted help center or support portal.",
        "freshdesk.com": "Domain points to Freshdesk - likely a Freshdesk-hosted helpdesk portal.",
        "intercom.help": "Domain points to Intercom - likely an Intercom-hosted help/support portal.",
        "drift.com": "Domain points to Drift - likely a Drift-hosted conversational marketing/sales surface.",
        "marketo.com": "Domain points to Marketo - likely a Marketo-hosted marketing landing page.",
        "pardot.com": "Domain points to Salesforce Pardot - likely a Pardot-hosted marketing landing page.",
        # SSO / IDP
        "okta.com": "Domain points to Okta - likely an Okta-hosted SSO/identity portal.",
        "auth0.com": "Domain points to Auth0 - likely an Auth0-hosted identity/SSO surface.",
        "pingone.com": "Domain points to Ping Identity - likely a Ping-hosted SSO/identity portal.",
        "onelogin.com": "Domain points to OneLogin - likely a OneLogin-hosted SSO portal.",
        # Forms / surveys / status / docs
        "typeform.com": "Domain points to Typeform - likely a Typeform-hosted form/survey.",
        "wufoo.com": "Domain points to Wufoo - likely a Wufoo-hosted form.",
        "formstack.com": "Domain points to Formstack - likely a Formstack-hosted form.",
        "surveymonkey.com": "Domain points to SurveyMonkey - likely a SurveyMonkey-hosted survey.",
        "statuspage.io": "Domain points to Atlassian Statuspage - likely a public status page.",
        "instatus.com": "Domain points to Instatus - likely a public status page.",
        "readme.io": "Domain points to ReadMe - likely a ReadMe-hosted developer portal/docs.",
        "gitbook.io": "Domain points to GitBook - likely a GitBook-hosted documentation site.",
        "notion.site": "Domain points to Notion - likely a Notion-hosted public page or site.",
        # E-commerce
        "myshopify.com": "Domain points to Shopify - likely a Shopify-hosted storefront.",
        "shopifycloud.com": "Domain points to Shopify infrastructure - likely a Shopify-hosted property.",
        "bigcommerce.com": "Domain points to BigCommerce - likely a BigCommerce-hosted storefront.",
        "squarespace.com": "Domain points to Squarespace - likely a Squarespace-hosted site.",
        "wixdns.net": "Domain points to Wix - likely a Wix-hosted site.",
        # Transactional email
        "sendgrid.net": "Domain points to SendGrid - likely used for SendGrid transactional/marketing email branding (e.g. CNAME for tracking links).",
        "mailgun.org": "Domain points to Mailgun - likely used for Mailgun transactional email branding/tracking.",
        "postmarkapp.com": "Domain points to Postmark - likely used for Postmark transactional email branding/tracking.",
        "mandrillapp.com": "Domain points to Mandrill (Mailchimp) - likely used for Mandrill transactional email branding.",
        # Video / collaboration
        "zoom.us": "Domain points to Zoom - likely a custom Zoom Vanity URL.",
        "webex.com": "Domain points to Cisco Webex - likely a custom Webex Vanity URL.",
        # Analytics / product
        "pendo.io": "Domain points to Pendo - likely used for Pendo product analytics/onboarding.",
        "segment.com": "Domain points to Segment - likely used for Segment customer-data tracking.",
    }

    spf_records = {
        "_spf.salesforce.com": "Domain is allowing emails to be sent from Salesforce.com. This indicates a high liklihood of subscription to Salesforce services.",
        "_spf.google.com": "Domain is allowing emails to be sent from Google.com. This indicates the domain may utilize Gmail or other G-Suite product offerings.",
        "protection.outlook.com": "Domain is allowing emails to be sent from Microsoft.com. This strongly indicates the domain is utilzing Microsoft Hosted Exchange.",
        "service-now.com": "Domain is allowing emails to be sent from service-now.com. This strongly indicates the domain is using the Service Now helpdesk platform.",
        "mailsenders.netsuite.com": "Domain is allowing emails to be sent from NetSuite. This strongly indicates the domain is using NetSuite product offerings (ERP / Cloud Accounting).",
        "mktomail.com": "Domain is allowing emails to be sent from Marketo. This strongly indicates the domain is using the Marketo Marketing and Lead Generation platform.",
        "spf.mandrillapp.com": "Domain is allowing emails to be sent from Mandrill (MailChimp). This strongly indicates the domain is using the Mandrill product offering for transactional email.",
        "pphosted.com": "Domain is allowing emails to be sent from Proof Point. This strongly indicates the domain is utilizing Proof Point Managed email services.",
        "zendesk.com": "Domain is allowing emails to be sent from Zendesk. This strongly indicates the domain is utilizing Zendesk for help desk and ticketing purposes.",
        "mcsv.net": "Domain is allowing emails to be sent from MailChimp. This strongly indicates the domain is utilizing MailChimp for email marketing.",
        "freshdesk.com": "Domain is allowing emails to be sent from Freshdesk. This strongly indicates the domain is utilizing FreshDesk for helpdesk and ticketing services.",
        "spf.messagelabs.com": "Domain is likely utilizing Symantec MessageLabs/Email Security.cloud.",
        "spf.everycloudtech.com": "Domain is likely using EveryCloud (Now Hornet Security).",
        "spf.peopleclick.com": "Domain could be using PeopleFluent for talent management.",
        "exclaimer.net": "Domain could be using Exclaimer for signatures"
    }

    mx_records = {
        "google.com": "Google server as an email server. This strongly indicates the domain is utilizing Google as an email server.",
        "googlemail.com": "Google server as an email server. This strongly indicates the domain is utilizing Google as an email server.",
        "pphosted.com": "Proof Point server as an email server. This strongly indicates that Proof Point Managed Email Hosting is being used.",
        "zoho.com": "ZOHO server as an email server. This strongly indicates that ZOHO is being utilized for email services.",
        "protection.outlook.com": "Microsoft server as an email server. This strongly indicates the domain is utilizing Microsoft Hosted Exchange."
    }

    async def setup(self):
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        # RAW_DNS_RECORD: dedup by (host, rdtype, answer) - same record from multiple sources
        # DNS_NAME: dedup by host alone - CNAME checks only need to fire once per name
        if event.type == "RAW_DNS_RECORD":
            return hash((event.data["host"], event.data["type"], event.data["answer"])), "already processed this record"
        return hash((str(event.host), "DNS_NAME-cname-check")), "already CNAME-checked this name"


    # Signature matches are informational hints, not verified vulnerabilities.
    async def inspect_raw(self, event):
        domain = str(event.host)
        rdtype = event.data["type"]
        answer = event.data["answer"]

        if rdtype == "TXT":
            # check for known TXT verification records
            for keyword, description in self.txt_records.items():
                if keyword.lower() in answer.lower():
                    await self.emit_event(
                        {
                            "host": domain,
                            "name": f"DNS TXT signature: {keyword}",
                            "description": f"[{domain}] TXT {keyword}: {description}",
                            "severity": "INFO",
                            "confidence": "LOW",
                        },
                        "FINDING",
                        parent=event,
                        context=f"{{module}} analyzed TXT record on {domain} and found {{event.type}}: {keyword}",
                    )
            # check for SPF includes
            if "v=spf1" in answer.lower():
                for spf_host, description in self.spf_records.items():
                    if spf_host.lower() in answer.lower():
                        await self.emit_event(
                            {
                                "host": domain,
                                "name": f"DNS SPF signature: {spf_host}",
                                "description": f"[{domain}] SPF include {spf_host}: {description}",
                                "severity": "INFO",
                                "confidence": "LOW",
                            },
                            "FINDING",
                            parent=event,
                            context=f"{{module}} analyzed SPF record on {domain} and found {{event.type}}: {spf_host}",
                        )

        elif rdtype == "MX":
            for mx_host, description in self.mx_records.items():
                if mx_host.lower() in answer.lower():
                    await self.emit_event(
                        {
                            "host": domain,
                            "name": f"DNS MX signature: {mx_host}",
                            "description": f"[{domain}] MX {mx_host}: {description}",
                            "severity": "INFO",
                            "confidence": "LOW",
                        },
                        "FINDING",
                        parent=event,
                        context=f"{{module}} analyzed MX record on {domain} and found {{event.type}}: {mx_host}",
                    )

    async def inspect_dns_name(self, event):
        # CNAME data comes in via DNS_NAME events (dnsresolve.py filters CNAME out
        # of the RAW_DNS_RECORD stream - see dnsresolve.py:207).
        domain = str(event.host)

        # CNAME prefix check - fires on the hostname itself, no CNAME answer needed
        for prefix, description in self.cname_records.items():
            if domain.lower().startswith(prefix.lower()):
                await self.emit_event(
                    {
                        "host": domain,
                        "name": f"DNS name prefix: {prefix}",
                        "description": f"[{domain}] CNAME {prefix}: {description}",
                        "severity": "INFO",
                        "confidence": "LOW",
                    },
                    "FINDING",
                    parent=event,
                    context=f"{{module}} matched CNAME prefix on {domain}: {prefix}",
                )

        # CNAME target check - needs the actual CNAME answer(s) attached to the event
        cname_answers = event.raw_dns_records.get("CNAME", set()) if event.raw_dns_records else set()
        for cname_answer in cname_answers:
            # dnspython appends a trailing dot to the FQDN; strip it for display
            target = cname_answer.to_text().lower().rstrip(".")
            for provider, description in self.cname_providers.items():
                if provider.lower() in target:
                    await self.emit_event(
                        {
                            "host": domain,
                            "name": f"DNS CNAME signature: {provider}",
                            "description": f"[{target}] CNAME target {provider}: {description}",
                            "severity": "INFO",
                            "confidence": "LOW",
                        },
                        "FINDING",
                        parent=event,
                        context=f"{{module}} matched CNAME target on {domain} ({target}): {provider}",
                    )

    async def handle_event(self, event):
        if event.type == "RAW_DNS_RECORD":
            await self.inspect_raw(event)
        elif event.type == "DNS_NAME":
            await self.inspect_dns_name(event)
