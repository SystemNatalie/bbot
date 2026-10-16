from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class submd(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query sub.md API for subdomains",
        "created_date": "2025-04-29",
        "author": "@SystemNatalie",
        "auth_required": False,
    }

    class Config(BaseModuleConfig):
        api_key: str = Field("", description="sub.md API key (optional)", sensitive=True)

    base_url = "https://api.sub.md/v1/search"
    reject_wildcards = False

    async def request_url(self, query):
        kwargs = {}
        if self.api_key:
            kwargs["headers"] = {"Authorization": f"Bearer {self.api_key}"}
        url = f"{self.base_url}?apex={self.helpers.quote(query)}"
        return await self.api_request(url, **kwargs)

    async def parse_results(self, r, query=None):
        results = set()
        for line in r.text.splitlines():
            hostname = line.strip().lower()
            if hostname:
                results.add(hostname)
        return results